import jpamb
import json

from dataclasses import dataclass
from typing import Callable, Union
from loguru import logger
from pathlib import Path\

from jpamb import jvm
from SignSet import SignSet
from TaintSet import TaintSet
from LengthAbstraction import LenInterval
from interpreter import Stack, PC, Bytecode
from jpamb.jvm.opcode import Return

suite = jpamb.Suite()
bc = Bytecode(suite, dict())

ANALYSIS_MODE = "sign"
TAINT_SOURCES = []
POSSIBLE_SINKS = {}
STRING_OPS = []
SANITIZERS = []

AValue = Union[SignSet, TaintSet, LenInterval]

def load_taint_config() -> dict:
    config_path = Path(__file__).parent / "taint_config.json"
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config.get("sql_injection", {})
    except FileNotFoundError:
        logger.warning(f"taint_config.json not found, using empty config")
        return {"sources": [], "sinks": {}, "propagators": [], "sanitizers": []}

if ANALYSIS_MODE == "sign":
    TOP = SignSet.top()
    BOT = SignSet.bot()

    # ints/booleans/chars mapped to {−,0,+} - not anymore ! =)
    def abstract_of_const(val: jvm.Value) -> SignSet:
        match val:
            case jvm.Value(type=jvm.Int(), value=v):
                return LenInterval.const(v)
            case jvm.Value(type=jvm.Boolean(), value=b):
                return LenInterval.const(1 if b else 0)
            case jvm.Value(type=jvm.Char(), value=c):
                return LenInterval.const(ord(c)) 
            case _:
                return SignSet.top()

elif ANALYSIS_MODE == "taint":
    TOP = TaintSet.top()
    BOT = TaintSet.bot()

    TAINT_CONFIG = load_taint_config()
    TAINT_SOURCES = TAINT_CONFIG.get("sources", [])
    POSSIBLE_SINKS = TAINT_CONFIG.get("sinks", {})
    STRING_OPS = TAINT_CONFIG.get("propagators", [])
    SANITIZERS = TAINT_CONFIG.get("sanitizers", [])

    def abstract_of_const(val: jvm.Value) -> TaintSet:
        return TaintSet.safe()
            
@dataclass
class AFrame:
    locals: dict[int, AValue]
    stack: Stack[AValue]
    pc: PC

    @staticmethod
    def from_method(method: jvm.AbsMethodID) -> "AFrame":
        return AFrame({}, Stack.empty(), PC(method, 0))

@dataclass
class AState:
    frames: Stack[AFrame]    
    status: str = "ok"        # possible statuses: "ok" / "divide by zero" /  "assertion" / ...
    aheap: dict[int, tuple[LenInterval, AValue]] = None # asbtract heap

    def __post_init__(self):
        if self.aheap is None:
            self.aheap = {}

def clone_frame(fr: AFrame) -> AFrame:
    return AFrame(dict(fr.locals), Stack(list(fr.stack.items)),
                  PC(fr.pc.method, fr.pc.offset))

def join_frames(a: AFrame, b: AFrame) -> AFrame:
    assert a.pc.method == b.pc.method and a.pc.offset == b.pc.offset
    new_locals = dict(a.locals)
    for k, v in b.locals.items():
        val_a = new_locals.get(k, BOT)
        new_locals[k] = join_values(val_a, v)
    sa, sb = len(a.stack.items), len(b.stack.items)
    if sa != sb:
        h = max(sa, sb)
        return AFrame(new_locals, Stack([TOP]*h), a.pc)
    new_stack = Stack([join_values(x, y) for x, y in zip(a.stack.items, b.stack.items)])
    return AFrame(new_locals, new_stack, a.pc)

def pc_key(pc: PC) -> tuple[jvm.AbsMethodID, int]:
    return (pc.method, pc.offset)

def not_negative_interval_from_sign(s: SignSet) -> LenInterval:
    if s == BOT:
        return LenInterval.top()
    if s.may_be_neg():
        return LenInterval.top()
    if s.may_be_zero():
        return LenInterval.const(0)
    if s.may_be_pos():
        return LenInterval(1, 10**12)
    
    return LenInterval(0, 10**12)

def interval_to_sign(L: LenInterval) -> SignSet:
    if L.lo == 0 and L.hi == 0: 
        return SignSet.zero()
    
    s = SignSet.bot()
    
    if L.lo < 0:
        s = s | SignSet.neg()
    
    if L.lo <= 0 and L.hi >= 0:
        s = s | SignSet.zero()
        
    if L.hi > 0:
        s = s | SignSet.pos()
    
    return s


def index_interval_from_sign(s: SignSet) -> tuple[int, int]:
    if s.zero:
        return(0, 0)
    if s.pos:
        return(1, 10**12)
    if s.may_be_neg() and not s.may_be_pos() and not s.zero:
        return (-10**12, -1)
    
    return (-10**12, 10**12)

def sign_to_interval(s: SignSet) -> LenInterval:
    if s.is_bot():
        return LenInterval(1, 0) 
        
    if s.may_be_neg():
        lo = -10**12
    elif s.may_be_zero():
        lo = 0
    else: 
        lo = 1
        
    if s.may_be_pos():
        hi = 10**12
    elif s.may_be_zero():
        hi = 0
    else:
        hi = -1
        
    return LenInterval(lo, hi)

def _combine_values(
    a: AValue, 
    b: AValue, 
    interval_op: Callable[[LenInterval, LenInterval], LenInterval]
) -> AValue:
    if isinstance(a, SignSet) and a.is_bot():
        return b
    if isinstance(b, SignSet) and b.is_bot():
        return a

    if isinstance(a, LenInterval) and isinstance(b, SignSet):
        b = sign_to_interval(b)
    elif isinstance(a, SignSet) and isinstance(b, LenInterval):
        a = sign_to_interval(a)

    if isinstance(a, LenInterval) and isinstance(b, LenInterval):
        return interval_op(a, b)

    return a | b

def join_values(a: AValue, b: AValue) -> AValue:
    return _combine_values(a, b, LenInterval.join)

def widen_values(a: AValue, b: AValue) -> AValue:
    return _combine_values(a, b, LenInterval.widening)


def step_A(states_at_pc: dict[PC, AState]) -> dict[PC, AState | str]: 
    if ANALYSIS_MODE == "sign":
        return step_A_sign(states_at_pc)
    elif ANALYSIS_MODE == "taint":
        return step_A_taint(states_at_pc)
    else:
        raise ValueError(f"Unknown analysis being run")
    
def to_sign(val: AValue) -> SignSet:
    if isinstance(val, SignSet):
        return val
    if isinstance(val, LenInterval):
        return interval_to_sign(val)
    return TOP

def to_index_range(val: AValue) -> tuple[int, int]:
    if isinstance(val, LenInterval):
        return (val.lo, val.hi)
    if isinstance(val, SignSet):
        return index_interval_from_sign(val)
    return (-10**12, 10**12) 

def to_len_interval_from_size(val: AValue) -> LenInterval:
    if isinstance(val, LenInterval):
        return LenInterval(max(0, val.lo), val.hi)
    if isinstance(val, SignSet):
        return not_negative_interval_from_sign(val)
    return LenInterval.top()

def refine_intervals(v1: LenInterval, v2: LenInterval, cond: str):
    t1, t2 = v1, v2
    f1, f2 = v1, v2
    
    if cond == "lt": 
        t1 = t1.meet(LenInterval(LenInterval.NEG_INF_VAL, v2.hi - 1))
        t2 = t2.meet(LenInterval(v1.lo + 1, LenInterval.INF_VAL))
        f1 = f1.meet(LenInterval(v2.lo, LenInterval.INF_VAL))
        f2 = f2.meet(LenInterval(LenInterval.NEG_INF_VAL, v1.hi))
        
    elif cond == "le": 
        t1 = t1.meet(LenInterval(LenInterval.NEG_INF_VAL, v2.hi))
        t2 = t2.meet(LenInterval(v1.lo, LenInterval.INF_VAL))
        f1 = f1.meet(LenInterval(v2.lo + 1, LenInterval.INF_VAL))
        f2 = f2.meet(LenInterval(LenInterval.NEG_INF_VAL, v1.hi - 1))
        
    elif cond == "gt": 
        t1 = t1.meet(LenInterval(v2.lo + 1, LenInterval.INF_VAL))
        t2 = t2.meet(LenInterval(LenInterval.NEG_INF_VAL, v1.hi - 1))
        f1 = f1.meet(LenInterval(LenInterval.NEG_INF_VAL, v2.hi))
        f2 = f2.meet(LenInterval(v1.lo, LenInterval.INF_VAL))
        
    elif cond == "ge": 
        t1 = t1.meet(LenInterval(v2.lo, LenInterval.INF_VAL))
        t2 = t2.meet(LenInterval(LenInterval.NEG_INF_VAL, v1.hi))
        f1 = f1.meet(LenInterval(LenInterval.NEG_INF_VAL, v2.hi - 1))
        f2 = f2.meet(LenInterval(v1.lo + 1, LenInterval.INF_VAL))
        
    elif cond == "eq":
        t1 = t1.meet(v2)
        t2 = t2.meet(v1)
        
    elif cond == "ne":
        f1 = f1.meet(v2)
        f2 = f2.meet(v1)

    return t1, t2, f1, f2

def step_A_sign(states_at_pc: dict[PC, AState]) -> dict[PC, AState | str]:
    out: dict[PC, AState | str] = {}

    def put(pc: PC, val: AState | str):
        k = (pc.method, pc.offset) 
        prev = out.get(k)
        if prev is None: 
            out[k] = val; 
            return
        if isinstance(prev, str) or isinstance(val, str):
            out[k] = prev if isinstance(prev, str) else val
            return
        a, b = prev.frames.peek(), val.frames.peek()
        joined_frame = AState(frames=Stack.empty().push(join_frames(a, b)), status="ok")

        joined_frame.status = prev.status if prev.status != "ok" else val.status

        joined_heap = dict(prev.aheap)
        for ref, (L, content) in val.aheap.items():
            if ref in joined_heap:
                prev_L, prev_content = joined_heap[ref]
                joined_heap[ref] = (prev_L.join(L), join_values(prev_content, content))
            else:
                joined_heap[ref] = (L, content)
        joined_frame.aheap = joined_heap

        out[k] = joined_frame

    for pc, entry in states_at_pc.items():

        assert isinstance(entry, AState)
        frame = entry.frames.peek()
        opr = bc[frame.pc]

        def succ(newf: AFrame, status: str = "ok"):
            put(newf.pc, AState(frames=Stack.empty().push(newf), status=status, aheap=dict(entry.aheap)))

        def succ_with_heap(newf: AFrame, heap: dict[int, LenInterval], status: str = "ok"):
            put(newf.pc, AState(frames=Stack.empty().push(newf), status=status, aheap=dict(heap)))

        match opr:
            case jvm.Push(value=v):
                nf = clone_frame(frame); 
                nf.stack.push(abstract_of_const(v)); 
                nf.pc += 1; 
                succ(nf)
            case jvm.Load(type=_t, index=idx):
                nf = clone_frame(frame); 
                nf.stack.push(nf.locals.get(idx, TOP)); 
                nf.pc += 1; 
                succ(nf)
            case jvm.New(classname=cname):
                nf = clone_frame(frame)
                nf.stack.push(TOP) 
                nf.pc += 1
                
                if cname.name == "java/lang/AssertionError":
                    succ(nf, status="assertion error")
                else:
                    succ(nf)
            case jvm.Throw():
                continue
            case jvm.Get(field=field, static=static):
                nf = clone_frame(frame)
                if field.extension.name == "$assertionsDisabled":
                    nf.stack.push(SignSet.zero())
                else:
                    nf.stack.push(TOP)
                nf.pc += 1
                succ(nf)
            case jvm.Store(type=_t, index=idx):
                if not frame.stack: 
                    continue
                nf = clone_frame(frame); 
                v = nf.stack.pop(); 
                nf.locals[idx] = v; 
                nf.pc += 1; 
                succ(nf)
            case jvm.Dup():
                if not frame.stack: 
                    continue
                nf = clone_frame(frame); 
                nf.stack.push(nf.stack.peek()); 
                nf.pc += 1; 
                succ(nf)

            # Int arithmetic
            case jvm.Binary(type=jvm.Int(), operant=oper):
                if len(frame.stack.items) < 2: 
                    continue
                nf = clone_frame(frame); 
                b, a = nf.stack.pop(), nf.stack.pop()

                if isinstance(a, LenInterval) and isinstance(b, LenInterval):
                    result: LenInterval | None = None
                    match oper:
                        case jvm.BinaryOpr.Add:
                            result = a.add(b) 
                        case jvm.BinaryOpr.Sub:
                            result = a.sub(b) 
                        case jvm.BinaryOpr.Mul:
                            result = a.mul(b)
                        case jvm.BinaryOpr.Div:
                            q, dz = a.div(b)
                            if not dz: 
                                result = q 
                        case _:
                            pass 
                    
                    if result is not None:
                        nf.stack.push(result)
                        nf.pc += 1
                        succ(nf)
                        continue 
            
                a_sign = to_sign(a)
                b_sign = to_sign(b)

                match oper:
                    case jvm.BinaryOpr.Add:
                        nf.stack.push(a_sign.add(b_sign)); 
                        nf.pc += 1; 
                        succ(nf)
                    case jvm.BinaryOpr.Sub:
                        nf.stack.push(a_sign.sub(b_sign)); 
                        nf.pc += 1; 
                        succ(nf)
                    case jvm.BinaryOpr.Mul:
                        nf.stack.push(a_sign.mul(b_sign)); 
                        nf.pc += 1; 
                        succ(nf)

                    case jvm.BinaryOpr.Div:
                        q, dz = a_sign.div(b_sign)
                        if q.signs:
                            nf_ok = clone_frame(nf); nf_ok.stack.push(q); nf_ok.pc += 1
                            succ(nf_ok)
                        if dz:
                            nf_err = clone_frame(nf); nf_err.pc += 1
                            succ(nf_err, status="divide by zero")
                            continue 

                    case jvm.BinaryOpr.Rem:
                        r, dz = a_sign.rem(b_sign)
                        if r.signs:
                            nf_ok = clone_frame(nf); nf_ok.stack.push(r); nf_ok.pc += 1
                            succ(nf_ok)
                        if dz:
                            nf_err = clone_frame(nf); nf_err.pc += 1
                            succ(nf_err, status="divide by zero")
                        continue 

                    case _:
                        nf.stack.push(TOP)
                        nf.pc += 1 
                        succ(nf)

            case jvm.Ifz(condition=cond, target=target):
                if not frame.stack: continue
                nf = clone_frame(frame); v = nf.stack.pop()

                v_sign = to_sign(v)

                may_take_branch = False
                may_fall_through = False

                match cond:
                    case "eq": 
                        may_take_branch = v_sign.may_be_zero()
                        may_fall_through = v_sign.may_be_nonzero()
                    case "ne": 
                        may_take_branch = v_sign.may_be_nonzero()
                        may_fall_through = v_sign.may_be_zero()
                    case "lt": 
                        may_take_branch = v_sign.may_be_neg()
                        may_fall_through = v_sign.may_be_zero() or v_sign.may_be_pos()
                    case "ge": 
                        may_take_branch = v_sign.may_be_zero() or v_sign.may_be_pos()
                        may_fall_through = v_sign.may_be_neg()
                    case "gt": 
                        may_take_branch = v_sign.may_be_pos()
                        may_fall_through = v_sign.may_be_neg() or v_sign.may_be_zero()
                    case "le": 
                        may_take_branch = v_sign.may_be_neg() or v_sign.may_be_zero()
                        may_fall_through = v_sign.may_be_pos()

                if may_take_branch:
                    jf = clone_frame(nf)
                    jf.pc.replace(target)
                    succ(jf)
                
                if may_fall_through:
                    ff = clone_frame(nf)
                    ff.pc += 1
                    succ(ff)
            case jvm.Goto(target=target):
                nf = clone_frame(frame)
                nf.pc.replace(target)   
                succ(nf)       

            case jvm.If(condition=cond, target=target):
                if len(frame.stack.items) < 2: 
                    continue
                nf = clone_frame(frame)
                val_v2 = nf.stack.pop() 
                val_v1 = nf.stack.pop()
                
                diff = None
                if isinstance(val_v1, LenInterval) and isinstance(val_v2, LenInterval):
                    diff = val_v1.sub(val_v2)
                
                diff_sign = to_sign(diff) if diff else to_sign(val_v1).sub(to_sign(val_v2))

                may_take_branch = False
                may_fall_through = False

                match cond:
                    case "eq": 
                        may_take_branch = diff_sign.may_be_zero()
                        may_fall_through = diff_sign.may_be_nonzero()
                    case "ne": 
                        may_take_branch = diff_sign.may_be_nonzero()
                        may_fall_through = diff_sign.may_be_zero()
                    case "lt": 
                        may_take_branch = diff_sign.may_be_neg()
                        may_fall_through = not diff_sign.le(SignSet.neg())
                    case "ge": 
                        may_take_branch = diff_sign.may_be_zero() or diff_sign.may_be_pos()
                        may_fall_through = diff_sign.may_be_neg()
                    case "gt": 
                        may_take_branch = diff_sign.may_be_pos()
                        may_fall_through = diff_sign.may_be_neg() or diff_sign.may_be_zero()
                    case "le": 
                        may_take_branch = diff_sign.may_be_neg() or diff_sign.may_be_zero()
                        may_fall_through = diff_sign.may_be_pos()

                t1, t2, f1, f2 = val_v1, val_v2, val_v1, val_v2
                if isinstance(val_v1, LenInterval) and isinstance(val_v2, LenInterval):
                    t1, t2, f1, f2 = refine_intervals(val_v1, val_v2, cond)

                def try_update_locals(target_frame, refined_v1, refined_v2):
                    method = frame.pc.method
                    curr_offset = frame.pc.offset
                    
                    def get_prev_op(start_offset):
                        for delta in range(1, 6): 
                            try:
                                p = PC(method, start_offset - delta)
                                return p, bc[p]
                            except (KeyError, IndexError, TypeError):
                                pass
                        return None, None

                    pc1, op1 = get_prev_op(curr_offset)
                    if not op1: return

                    pc2, op2 = get_prev_op(pc1.offset)
                    if not op2: return

                    if isinstance(op1, jvm.Load) and isinstance(op2, jvm.Load):
                        target_frame.locals[op2.index] = refined_v1
                        target_frame.locals[op1.index] = refined_v2

                if may_take_branch:
                    jf = clone_frame(nf)
                    jf.pc.replace(target)
                    try_update_locals(jf, t1, t2)
                    succ(jf)
                
                if may_fall_through:
                    ff = clone_frame(nf)
                    ff.pc += 1
                    try_update_locals(ff, f1, f2)
                    succ(ff)

            case jvm.NewArray(type=type, dim=dim):
                if not frame.stack: continue
                nf = clone_frame(frame)
                size_val = nf.stack.pop()
                L = to_len_interval_from_size(size_val)
                next_ref = max(entry.aheap.keys(), default=-1) + 1
                nf.stack.push(LenInterval.const(next_ref)) 
                nf.pc += 1
                
                new_heap = dict(entry.aheap)
                new_heap[next_ref] = (L, LenInterval.const(0))
                succ_with_heap(nf, new_heap)

            case jvm.ArrayLength():
                if not frame.stack: continue
                nf = clone_frame(frame)
                aref = nf.stack.pop()
                
                length = LenInterval.top()
                if isinstance(aref, LenInterval) and aref.lo == aref.hi:
                    if aref.lo in entry.aheap:
                        length = entry.aheap[aref.lo][0]

                nf.stack.push(length) 
                nf.pc += 1
                succ_with_heap(nf, entry.aheap)

            case jvm.ArrayLoad(type=type):
                if len(frame.stack.items) < 2: continue
                nf = clone_frame(frame)
                
                idx_val = nf.stack.pop()
                aref = nf.stack.pop()

                L = LenInterval.top()
                content = TOP 
                
                if isinstance(aref, LenInterval) and aref.lo == aref.hi:
                    ref_id = aref.lo
                    if ref_id in entry.aheap:
                        heap_obj = entry.aheap[ref_id]
                        if len(heap_obj) == 3:
                            L, summary, elements = heap_obj
                            
                            if idx_val.lo == idx_val.hi and idx_val.lo in elements:
                                content = elements[idx_val.lo]
                            else:
                                content = summary
                        else:
                            L, content = heap_obj

                idx_min, idx_max = to_index_range(idx_val)
                may_in, may_oob = L.may_contain_index(idx_min, idx_max)

                if may_in:
                    nf_ok = clone_frame(nf)
                    nf_ok.stack.push(content)
                    nf_ok.pc += 1
                    succ_with_heap(nf_ok, entry.aheap)

                if may_oob: 
                    nf_err = clone_frame(nf)
                    nf_err.pc += 1
                    succ_with_heap(nf_err, entry.aheap, status="out of bounds")

            case jvm.ArrayStore(type=jvm.Int()):
                if len(frame.stack.items) < 3: 
                    continue
                nf = clone_frame(frame)
                v_sign = nf.stack.pop()
                idx_val = nf.stack.pop()
                aref = nf.stack.pop()

                L = LenInterval.top()

                idx_min, idx_max = to_index_range(idx_val)
                may_in, may_oob = L.may_contain_index(idx_min, idx_max)

                nf_ok = clone_frame(nf); nf_ok.pc += 1
                if may_in:
                    new_heap = dict(entry.aheap)
                    
                    if isinstance(aref, LenInterval) and aref.lo == aref.hi:
                        ref_id = aref.lo
                        if ref_id in new_heap:
                            heap_obj = new_heap[ref_id]

                            is_exact_index = (isinstance(idx_val, LenInterval) and idx_val.lo == idx_val.hi)
                            
                            if len(heap_obj) == 3:
                                L_arr, summary, elements = heap_obj
                                
                                if is_exact_index:
                                    new_elements = dict(elements)
                                    new_elements[idx_val.lo] = v_sign 
                                    new_heap[ref_id] = (L_arr, summary, new_elements)
                                else:
                                    new_summary = join_values(summary, v_sign)
                                    for elem_val in elements.values():
                                        new_summary = join_values(new_summary, elem_val)
                                    
                                    new_heap[ref_id] = (L_arr, new_summary)

                            elif len(heap_obj) == 2:
                                L_arr, old_content = heap_obj
                                new_content = join_values(old_content, v_sign)
                                new_heap[ref_id] = (L_arr, new_content)

                    succ_with_heap(nf_ok, new_heap)

            case jvm.InvokeVirtual(method=m) | jvm.InvokeStatic(method=m) | jvm.InvokeSpecial(method=m):
                method_str = str(m)

                if "assertIf:(Z)V" in method_str:
                    nf = clone_frame(frame)
                    num_args = len(m.extension.params)
                    has_receiver = not isinstance(opr, jvm.InvokeStatic)
                    total_to_pop = num_args + (1 if has_receiver else 0)

                    args = frame.stack.items[-num_args:] if num_args <= len(frame.stack.items) else []

                    for _ in range(total_to_pop):
                        if nf.stack:
                            nf.stack.pop()

                    if args:
                        cond_val = args[-1]
                        cond_sign = to_sign(cond_val)

                        may_true = cond_sign.may_be_nonzero()
                        may_false = cond_sign.may_be_zero()

                        nf.pc += 1

                        if may_false:
                            nf_err = clone_frame(nf)
                            succ(nf_err, status="assertion error")
                        if may_true:
                            nf_ok = clone_frame(nf)
                            succ(nf_ok)
                    else:
                        nf.pc += 1
                        succ(nf)

                    continue

                nf = clone_frame(frame)
                nf.pc += 1
                succ(nf)

            case jvm.Return(type=None):
                continue

            case jvm.Return(type=_t):
                continue

            case _:
                nf = clone_frame(frame); 
                nf.pc += 1; 
                succ(nf)

    return out

def step_A_taint(states_at_pc: dict[PC, AState]) -> dict[PC, AState | str]:
    out: dict[PC, AState | str] = {}

    def put(pc: PC, val: AState | str):
        k = (pc.method, pc.offset) 
        prev = out.get(k)
        if prev is None: 
            out[k] = val; 
            return
        if isinstance(prev, str) or isinstance(val, str):
            out[k] = prev if isinstance(prev, str) else val
            return
        a, b = prev.frames.peek(), val.frames.peek()
        out[k] = AState(frames=Stack.empty().push(join_frames(a, b)))

    for pc, entry in states_at_pc.items():
        assert isinstance(entry, AState)
        frame = entry.frames.peek()
        opr = bc[frame.pc]

        def succ(newf: AFrame, status: str = "ok"):
            put(newf.pc, AState(frames=Stack.empty().push(newf), status=status))
        

        match opr:
            case jvm.Load(type=_t, index=idx):
                nf = clone_frame(frame)
                nf.stack.push(nf.locals.get(idx, TOP))
                nf.pc += 1
                succ(nf)
            case jvm.Store(type=_t, index=idx):
                if not frame.stack:
                    continue
                nf = clone_frame(frame)
                v = nf.stack.pop()
                nf.locals[idx] = v
                nf.pc += 1
                succ(nf)
            case jvm.Push(value=v):
                nf = clone_frame(frame)
                # String literals are safe, everything else irrelevant
                nf.stack.push(abstract_of_const(v))
                nf.pc += 1
                succ(nf)
            case jvm.Get(field=field, static=static):
                nf = clone_frame(frame)
                nf.stack.push(TOP)  # Unknown taint
                nf.pc += 1
                succ(nf)
            case jvm.New(classname=cname):
                nf = clone_frame(frame)
                nf.stack.push(TaintSet.safe())  # New objects start safe
                nf.pc += 1
                succ(nf)
            case jvm.Dup():
                if not frame.stack:
                    continue
                nf = clone_frame(frame)
                nf.stack.push(nf.stack.peek())
                nf.pc += 1
                succ(nf)
            case jvm.InvokeVirtual(method=m) | jvm.InvokeStatic(method=m) | jvm.InvokeSpecial(method=m):
                method_str = str(m)
                
                if any(src in method_str for src in TAINT_SOURCES):
                    nf = clone_frame(frame)
                    num_to_pop = len(m.extension.params)
                    if not isinstance(opr, jvm.InvokeStatic):
                        num_to_pop += 1  
                    for _ in range(num_to_pop):
                        if nf.stack:
                            nf.stack.pop()
                    nf.stack.push(TaintSet.tainted()) 
                    nf.pc += 1
                    succ(nf)
                    continue
                
                sink_method = next((key for key in POSSIBLE_SINKS.keys() if key in method_str), None)
                if sink_method:
                    vulnerable_params = POSSIBLE_SINKS[sink_method]
                    num_args = len(m.extension.params)
                    if not isinstance(opr, jvm.InvokeStatic):
                        num_args += 1
                    
                    sql_tainted = False
                    
                    if vulnerable_params:
                        # Check only specific parameters
                        for param_idx in vulnerable_params:
                            if len(frame.stack.items) > param_idx:
                                arg = frame.stack.items[-(param_idx+1)]
                                if hasattr(arg, 'is_tainted') and arg.is_tainted():
                                    sql_tainted = True
                                    break
                    else:
                        # Empty list means check all parameters
                        for i in range(num_args):
                            if len(frame.stack.items) > i:
                                arg = frame.stack.items[-(i+1)]
                                if hasattr(arg, 'is_tainted') and arg.is_tainted():
                                    sql_tainted = True
                                    break
                    
                    nf = clone_frame(frame)
                    for _ in range(num_args):
                        if nf.stack:
                            nf.stack.pop()
                    nf.pc += 1
                    
                    if sql_tainted:
                        succ(nf, status="SQL injection")
                    else:
                        if m.extension.return_type is not None:
                            nf.stack.push(TaintSet.safe())
                        succ(nf)
                    continue

                if any(sanitizer in method_str for sanitizer in SANITIZERS):
                    num_args = len(m.extension.params)
                    if not isinstance(opr, jvm.InvokeStatic):
                        num_args += 1
                    
                    nf = clone_frame(frame)
                    for _ in range(num_args):
                        if nf.stack:
                            nf.stack.pop()
                    
                    # Sanitizers always produce SAFE output
                    if m.extension.return_type is not None:
                        nf.stack.push(TaintSet.safe())
                    nf.pc += 1
                    succ(nf)
                    continue
                
                if any(str_op in method_str for str_op in STRING_OPS):
                    num_args = len(m.extension.params)
                    if not isinstance(opr, jvm.InvokeStatic):
                        num_args += 1  
                    
                    any_tainted = False
                    for i in range(min(num_args, len(frame.stack.items))):
                        arg = frame.stack.items[-(i+1)]
                        if hasattr(arg, 'is_tainted') and arg.is_tainted():
                            any_tainted = True
                            break
                    
                    nf = clone_frame(frame)
                    for _ in range(num_args):
                        if nf.stack:
                            nf.stack.pop()
                    
                    if m.extension.return_type is not None:
                        nf.stack.push(TaintSet.tainted() if any_tainted else TaintSet.safe())
                    nf.pc += 1
                    succ(nf)
                    continue
                
                nf = clone_frame(frame)
                num_to_pop = len(m.extension.params)
                if not isinstance(opr, jvm.InvokeStatic):
                    num_to_pop += 1
                
                any_tainted = False
                for i in range(min(num_to_pop, len(frame.stack.items))):
                    arg = frame.stack.items[-(i+1)]
                    if hasattr(arg, 'is_tainted') and arg.is_tainted():
                        any_tainted = True
                        break
                
                for _ in range(num_to_pop):
                    if nf.stack:
                        nf.stack.pop()
                
                if m.extension.return_type is not None:
                    nf.stack.push(TaintSet.tainted() if any_tainted else TOP)
                nf.pc += 1
                succ(nf)
            case jvm.Ifz(condition=cond, target=target):
                if not frame.stack:
                    continue
                nf = clone_frame(frame)
                nf.stack.pop() 
                
                jf = clone_frame(nf)
                jf.pc.replace(target)
                succ(jf)
                
                ff = clone_frame(nf)
                ff.pc += 1
                succ(ff)
            case jvm.If(condition=cond, target=target):
                if len(frame.stack.items) < 2:
                    continue
                nf = clone_frame(frame)
                nf.stack.pop()
                nf.stack.pop()
                
                jf = clone_frame(nf)
                jf.pc.replace(target)
                succ(jf)
                
                ff = clone_frame(nf)
                ff.pc += 1
                succ(ff)
            case jvm.Goto(target=target):
                nf = clone_frame(frame)
                nf.pc.replace(target)
                succ(nf)
            case jvm.Return(type=None) | jvm.Return(type=_):
                continue
            case _:
                nf = clone_frame(frame)
                nf.pc += 1
                succ(nf)

    return out

def _join_states(prev: AState | str, cur: AState | str) -> AState | str:
    if isinstance(prev, str) and isinstance(cur, str):
        return prev if prev == cur else "error_merge" # Simplify status merge
    if isinstance(prev, str): return prev                    
    if isinstance(cur, str): return cur
    
    a, b = prev.frames.peek(), cur.frames.peek()
    jf = join_frames(a, b)
    
    status = prev.status if prev.status != "ok" else cur.status
    
    joined_heap = dict(prev.aheap)
    
    for ref, val_cur in cur.aheap.items():
        if ref not in joined_heap:
            joined_heap[ref] = val_cur
            continue

        val_prev = joined_heap[ref]
        
        if ANALYSIS_MODE == "sign":
            
            is_prev_precise = (len(val_prev) == 3)
            is_cur_precise = (len(val_cur) == 3)

            L_prev = val_prev[0]
            summary_prev = val_prev[1]
            
            L_cur = val_cur[0]
            summary_cur = val_cur[1]

            new_L = L_prev.join(L_cur)
            new_summary = join_values(summary_prev, summary_cur)

            if is_prev_precise and is_cur_precise:
                elems_prev = val_prev[2]
                elems_cur = val_cur[2]
                new_elems = {}
                
                all_indices = set(elems_prev.keys()) | set(elems_cur.keys())
                
                if len(all_indices) > 20:
                    final_summary = new_summary
                    for v in elems_prev.values(): final_summary = join_values(final_summary, v)
                    for v in elems_cur.values(): final_summary = join_values(final_summary, v)
                    joined_heap[ref] = (new_L, final_summary)
                else:
                    for idx in all_indices:
                        v_p = elems_prev.get(idx, summary_prev)
                        v_c = elems_cur.get(idx, summary_cur)
                        new_elems[idx] = join_values(v_p, v_c)
                    
                    joined_heap[ref] = (new_L, new_summary, new_elems)
            
            else:
                
                final_summary = new_summary
                
                if is_prev_precise:
                    for v in val_prev[2].values(): 
                        final_summary = join_values(final_summary, v)
                
                if is_cur_precise:
                    for v in val_cur[2].values(): 
                        final_summary = join_values(final_summary, v)
                        
                joined_heap[ref] = (new_L, final_summary)

        else:
            joined_heap[ref] = val_prev 

    return AState(frames=Stack.empty().push(jf), status=status, aheap=joined_heap)

def _state_equal(a: AState | str, b: AState | str) -> bool:
    if isinstance(a, str) or isinstance(b, str):
        return a == b
    af, bf = a.frames.peek(), b.frames.peek()
    heaps_equal = (
    a.aheap.keys() == b.aheap.keys() and all(a.aheap[k] == b.aheap[k] for k in a.aheap))
    return (af.pc.method == bf.pc.method and af.pc.offset == bf.pc.offset
            and af.locals == bf.locals and af.stack.items == bf.stack.items
            and a.status == b.status and heaps_equal)

def execute_A(methodid, input):
    af = AFrame.from_method(methodid)

    start_heap = {}
    heap_counter = 0

    for i, v in enumerate(input.values):
        if ANALYSIS_MODE == "sign" and isinstance(v.type, jvm.Array):
            elements = {}
            summary_content = BOT
            
            for idx, elem in enumerate(v.value):
                # Char/Int conversion
                val_int = ord(elem) if isinstance(elem, str) and len(elem) == 1 else elem
                val_interval = LenInterval.const(val_int)
                
                if len(v.value) < 20: 
                    elements[idx] = val_interval
                
                summary_content = join_values(summary_content, val_interval)
            
            length = LenInterval.const(len(v.value))
            start_heap[heap_counter] = (length, summary_content, elements)
            
            af.locals[i] = LenInterval.const(heap_counter)
            heap_counter += 1
        else:
            af.locals[i] = abstract_of_const(v)

    start = AState(frames=Stack.empty().push(af), status="ok", aheap=start_heap)

    k0 = pc_key(af.pc)

    #seen: dict[tuple[jvm.AbsMethodID,int], AState | str] = { k0: start }
    #frontier: dict[tuple[jvm.AbsMethodID,int], AState | str] = { k0: start }
    seen = { k0: start }
    frontier = { k0: start }

    visit_counts = { k0: 1 }

    STEPS_LIMIT = 1_000_000
    steps = 0

    while frontier and steps < STEPS_LIMIT:
        steps += 1
        nxt = step_A(frontier)

        new_frontier: dict[PC, AState | str] = {}

        for pc, val in nxt.items():
            current_count = visit_counts.get(pc, 0) + 1
            visit_counts[pc] = current_count

            if pc not in seen:
                seen[pc] = val
                new_frontier[pc] = val
                continue

            joined = _join_states(seen[pc], val)

            WIDENING_THRESHOLD = 10

            should_widen = (ANALYSIS_MODE == "sign" 
                            and not isinstance(joined, str) 
                            and not isinstance(seen[pc], str)
                            and current_count > WIDENING_THRESHOLD)

            if should_widen:
                prev_frame = seen[pc].frames.peek()
                curr_frame = joined.frames.peek() 
                
                prev_heap = seen[pc].aheap
                widened_heap = dict(joined.aheap)

                def norm_heap_entry(h):
                    if isinstance(h, tuple):
                        if len(h) == 2:
                            L, summary = h
                            return L, summary
                        elif len(h) == 3:
                            L, summary, elems = h
                            return L, summary
                    return LenInterval.top(), BOT

                for ref, cur_val in joined.aheap.items():
                    if ref in prev_heap:
                        prev_val = prev_heap[ref]

                        L_prev, c_prev = norm_heap_entry(prev_val)
                        L_joined, c_joined = norm_heap_entry(cur_val)

                        widen_L = L_prev.widening(L_joined)
                        widen_c = widen_values(c_prev, c_joined)
                        widened_heap[ref] = (widen_L, widen_c)

                joined.aheap = widened_heap


                new_locals = dict(curr_frame.locals)
                for k, v_curr in new_locals.items():
                    if k in prev_frame.locals:
                        v_prev = prev_frame.locals[k]
                        new_locals[k] = widen_values(v_prev, v_curr)
                curr_frame.locals = new_locals

                if len(prev_frame.stack.items) == len(curr_frame.stack.items):
                    new_stack_items = []
                    for v_prev, v_curr in zip(prev_frame.stack.items, curr_frame.stack.items):
                        new_stack_items.append(widen_values(v_prev, v_curr))
                    curr_frame.stack = Stack(new_stack_items)

            if not _state_equal(joined, seen[pc]):
                seen[pc] = joined
                new_frontier[pc] = joined

        frontier = new_frontier

    if steps >= STEPS_LIMIT:
        logger.debug("Abstract fixpoint: step limit reached")

    statuses = [s.status for (m, _), s in seen.items() if isinstance(s, AState) and m == methodid]
    has_error = any(st != "ok" for st in statuses)
    found_return = any(
        m == methodid and isinstance(bc[PC(m, pc)], Return)
        for (m, pc) in seen
    )

    if not found_return and not has_error:
        seen[(methodid, -1)] = "non-terminating"

    return seen

def dump_A(seen: dict[tuple[jvm.AbsMethodID, int], AState | str]):
    final_status = "ok"

    for (method, offset), v in sorted(seen.items(), key=lambda it: (str(it[0][0]), it[0][1])):
        pc_s = f"{method}:{offset}"
        if isinstance(v, str):
            print(f"{pc_s}: <{v}>")
            if v == "non-terminating":
                final_status = "*"
            elif v != "ok":
                final_status = v
        else:
            fr = v.frames.peek()
            locs = ", ".join(f"{i}:{val}" for i, val in sorted(fr.locals.items()))
            stack = "[" + ", ".join(str(s) for s in fr.stack.items) + "]"
            heap_s = ", ".join(f"{r}:{L}" for r, L in sorted(v.aheap.items()))
            print(f"{pc_s}: status={v.status}  locals={{ {locs} }}  stack={stack}  heap={{ {heap_s} }}")

            if v.status != "ok":
                final_status = v.status

    if any(v == "*" for v in seen.values()):
        final_status = "*"

    print(final_status)



if __name__ == "__main__":
    methodid, input = jpamb.getcase()
    
    # Abstract run
    abstract_seen = execute_A(methodid, input)
    #print("== abstract ==")
    dump_A(abstract_seen)

