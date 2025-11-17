import jpamb

from dataclasses import dataclass
from jpamb import jvm
from SignSet import SignSet, TOP, BOT
from LengthAbstraction import LenInterval
from interpreter import Stack, PC, Bytecode
from loguru import logger

AValue = SignSet

suite = jpamb.Suite()
bc = Bytecode(suite, dict())

    
# ints/booleans/chars mapped to {−,0,+}
def sign_of_const(val: jvm.Value) -> SignSet:
    match val:
        case jvm.Value(type=jvm.Int(), value=v):
            return SignSet.of_int(v)
        case jvm.Value(type=jvm.Boolean(), value=b):
            return SignSet.of_int(1 if b else 0)
        case jvm.Value(type=jvm.Char(), value=c):
            #This will always return a positive value, because there are no negative Unicode values.
            return SignSet.of_int(ord(c))
        case _:
            return TOP  
            
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
    aheap: dict[int, LenInterval] = None # asbtract heap

    def __post_init__(self):
        if self.aheap is None:
            self.aheap = {}

# shallow copy 
def with_heap(fr: AFrame, aheap: dict[int, LenInterval]) -> AState:
    return AState(frames=Stack.empty().push(fr), status="ok", aheap=dict(aheap))



def clone_frame(fr: AFrame) -> AFrame:
    return AFrame(dict(fr.locals), Stack(list(fr.stack.items)),
                  PC(fr.pc.method, fr.pc.offset))

def join_frames(a: AFrame, b: AFrame) -> AFrame:
    assert a.pc.method == b.pc.method and a.pc.offset == b.pc.offset
    new_locals = dict(a.locals)
    for k, v in b.locals.items():
        new_locals[k] = new_locals.get(k, BOT) | v
    sa, sb = len(a.stack.items), len(b.stack.items)
    if sa != sb:
        h = max(sa, sb)
        return AFrame(new_locals, Stack([TOP]*h), a.pc)
    new_stack = Stack([x | y for x, y in zip(a.stack.items, b.stack.items)])
    return AFrame(new_locals, new_stack, a.pc)

def pc_key(pc: PC) -> tuple[jvm.AbsMethodID, int]:
    return (pc.method, pc.offset)

def key_of(fr: AFrame) -> tuple[jvm.AbsMethodID, int]:
    return (fr.pc.method, fr.pc.offset)

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
    z = (L.lo == 0 and L.hi == 0)
    if z: 
        return SignSet.zero()
    if L.lo >= 1:
        return SignSet.pos()
    
    return SignSet.zero() | SignSet.pos()

def index_interval_from_sign(s: SignSet) -> tuple[int, int]:
    if s.zero:
        return(0, 0)
    if s.pos:
        return(1, 10**12)
    if s.may_be_neg() and not s.may_be_pos() and not s.zero:
        return (-10**12, -1)
    
    return (-10**12, 10**12)

def step_A(states_at_pc: dict[PC, AState]) -> dict[PC, AState | str]: 
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
        for ref, L in val.aheap.items():
            if ref in joined_heap:
                joined_heap[ref] = joined_heap[ref].join(L)
            else:
                joined_heap[ref] = L
        joined_frame.aheap = joined_heap

        out[k] = joined_frame

    for pc, entry in states_at_pc.items():
        assert isinstance(entry, AState)
        frame = entry.frames.peek()
        opr = bc[frame.pc]

        def succ(newf: AFrame, status: str = "ok"):
            put(newf.pc, AState(frames=Stack.empty().push(newf), status=status))

        def succ_with_heap(newf: AFrame, heap: dict[int, LenInterval], status: str = "ok"):
            put(newf.pc, AState(frames=Stack.empty().push(newf), status=status, aheap=dict(heap)))

        

        match opr:
            case jvm.Push(value=v):
                nf = clone_frame(frame); 
                nf.stack.push(sign_of_const(v)); 
                nf.pc += 1; 
                succ(nf)
            case jvm.Load(type=_t, index=idx):
                nf = clone_frame(frame); 
                nf.stack.push(nf.locals.get(idx, TOP)); 
                nf.pc += 1; 
                succ(nf)
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
            case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Add):
                if len(frame.stack.items) < 2: 
                    continue
                nf = clone_frame(frame); 
                b,a = nf.stack.pop(), nf.stack.pop()
                nf.stack.push(a.add(b)); 
                nf.pc += 1; 
                succ(nf)

            case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Sub):
                if len(frame.stack.items) < 2: 
                    continue
                nf = clone_frame(frame); 
                b,a = nf.stack.pop(), nf.stack.pop() 
                nf.stack.push(a.sub(b)); 
                nf.pc += 1; 
                succ(nf)

            case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Mul):
                if len(frame.stack.items) < 2: 
                    continue
                nf = clone_frame(frame); 
                b,a = nf.stack.pop(), nf.stack.pop()
                nf.stack.push(a.mul(b)); 
                nf.pc += 1; 
                succ(nf)

            case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Div):
                if len(frame.stack.items) < 2: continue
                b, a = frame.stack.items[-1], frame.stack.items[-2]
                q, dz = a.div(b)
                if q.signs:
                    nf1 = clone_frame(frame)
                    nf1.stack = Stack(list(frame.stack.items)); nf1.stack.pop(); nf1.stack.pop()
                    nf1.stack.push(q); nf1.pc = PC(frame.pc.method, frame.pc.offset + 1)
                    succ(nf1)
                if dz:
                    nf_err = clone_frame(frame); nf_err.pc = PC(frame.pc.method, frame.pc.offset + 1)
                    succ(nf_err, status="divide by zero")

            case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Rem):
                if len(frame.stack.items) < 2: continue
                b, a = frame.stack.items[-1], frame.stack.items[-2]
                r, dz = a.rem(b)
                if r.signs:
                    nf1 = clone_frame(frame)
                    nf1.stack = Stack(list(frame.stack.items)); nf1.stack.pop(); nf1.stack.pop()
                    nf1.stack.push(r); nf1.pc = PC(frame.pc.method, frame.pc.offset + 1)
                    succ(nf1)
                if dz:
                    nf_err = clone_frame(frame); nf_err.pc = PC(frame.pc.method, frame.pc.offset + 1)
                    succ(nf_err, status="divide by zero")

            case jvm.Ifz(condition=cond, target=target):
                if not frame.stack: continue
                nf = clone_frame(frame); v = nf.stack.pop()
                if cond == "eq":
                    if v.may_be_zero():   
                        jf = clone_frame(nf); 
                        jf.pc.replace(target); 
                        succ(jf)
                    if v.may_be_nonzero(): 
                        ff = clone_frame(nf); 
                        ff.pc += 1; 
                        succ(ff)
                elif cond == "ne":
                    if v.may_be_nonzero(): 
                        jf = clone_frame(nf); 
                        jf.pc.replace(target); 
                        succ(jf)
                    if v.may_be_zero():     
                        ff = clone_frame(nf); 
                        ff.pc += 1; 
                        succ(ff)
                else:
                    ff = clone_frame(nf); 
                    ff.pc += 1; 
                    succ(ff)
            case jvm.Goto(target=target):
                nf = clone_frame(frame)
                nf.pc.replace(target)   
                succ(nf)       

            case jvm.If(condition=_cond, target=target):
                nf1 = clone_frame(frame); 
                nf1.pc.replace(target); 
                succ(nf1)
                nf2 = clone_frame(frame); 
                nf2.pc += 1; 
                succ(nf2)

            case jvm.NewArray(type=type, dim=dim):
                if not frame.stack:
                    continue
                nf = clone_frame(frame)
                size_sign = nf.stack.pop()

                L = not_negative_interval_from_sign(size_sign)

                # allocating abstract reference id
                next_ref = max(entry.aheap.keys(), default=-1) + 1

                nf.stack.push(TOP)

                nf.pc += 1

                new_heap = dict(entry.aheap)
                new_heap[next_ref] = L
                succ_with_heap(nf, new_heap)

            case jvm.ArrayLength():
                if not frame.stack:
                    continue
                nf = clone_frame(frame)
                aref = nf.stack.pop()

                L = LenInterval.top()

                nf.stack.push(interval_to_sign(L))
                nf.pc += 1
                succ_with_heap(nf, entry.aheap)

            case jvm.ArrayLoad(type=type):
                if len(frame.stack.items) < 2:
                    continue
                nf = clone_frame(frame)
                idx_sign = nf.stack.pop()
                aref = nf.stack.pop()

                L = LenInterval.top()

                idx_min, idx_max = index_interval_from_sign(idx_sign)
                may_in, may_oob = L.may_contain_index(idx_min, idx_max)

                nf_ok = clone_frame(nf)
                nf_ok.stack.push(TOP)
                nf_ok.pc += 1
                if may_in:
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
                idx_sign = nf.stack.pop()
                aref = nf.stack.pop()

                L = LenInterval.top()

                idx_min, idx_max = index_interval_from_sign(idx_sign)
                may_in, may_oob = L.may_contain_index(idx_min, idx_max)

                nf_ok = clone_frame(nf); nf_ok.pc += 1
                if may_in:
                    succ_with_heap(nf_ok, entry.aheap)
                if may_oob:
                    nf_err = clone_frame(nf); nf_err.pc += 1
                    succ_with_heap(nf_err, entry.aheap, status="out of bounds")


            
            case jvm.Return(type=None):
                continue

            case jvm.Return(type=_t):
                continue

            case _:
                nf = clone_frame(frame); 
                nf.pc += 1; 
                succ(nf)

    return out

def _join_states(prev: AState | str, cur: AState | str) -> AState | str:
    if isinstance(prev, str) and isinstance(cur, str):
        return prev
    if isinstance(prev, str):
        return prev                    
    if isinstance(cur, str):
        return cur
    a, b = prev.frames.peek(), cur.frames.peek()
    jf = join_frames(a, b)
    status = prev.status if prev.status != "ok" else cur.status
    joined_heap = dict(prev.aheap)
    for ref, L in cur.aheap.items():
        joined_heap[ref] = joined_heap.get(ref, L).join(L) if ref in joined_heap else L
    return AState(frames=Stack.empty().push(jf),
                  status=prev.status if prev.status != "ok" else cur.status, aheap=joined_heap)

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
    for i, v in enumerate(input.values):
        av = sign_of_const(v)
        af.locals[i] = av

    start_pc = af.pc
    start = AState(frames=Stack.empty().push(af), status="ok", aheap={})

    k0 = pc_key(af.pc)

    seen: dict[tuple[jvm.AbsMethodID,int], AState | str] = { k0: start }
    frontier: dict[tuple[jvm.AbsMethodID,int], AState | str] = { k0: start }

    STEPS_LIMIT = 1_000_000
    steps = 0

    while frontier and steps < STEPS_LIMIT:
        steps += 1
        nxt = step_A(frontier)

        new_frontier: dict[PC, AState | str] = {}

        for pc, val in nxt.items():
            if pc not in seen:
                seen[pc] = val
                new_frontier[pc] = val
                continue

            joined = _join_states(seen[pc], val)
            if not _state_equal(joined, seen[pc]):
                seen[pc] = joined
                new_frontier[pc] = joined

        frontier = new_frontier

    if steps >= STEPS_LIMIT:
        logger.debug("Abstract fixpoint: step limit reached")

    return seen

# output 
def dump_A(seen: dict[tuple[jvm.AbsMethodID, int], AState | str]):
    final_status = "ok" 

    for (method, offset), v in sorted(seen.items(), key=lambda it: (str(it[0][0]), it[0][1])):
        pc_s = f"{method}:{offset}"
        if isinstance(v, str):
            print(f"{pc_s}: <{v}>")
            if v != "ok":
                final_status = v
        else:
            fr = v.frames.peek()
            locs = ", ".join(f"{i}:{val}" for i, val in sorted(fr.locals.items()))
            stack = "[" + ", ".join(str(s) for s in fr.stack.items) + "]"
            heap_s = ", ".join(f"{r}:{L}" for r, L in sorted(v.aheap.items()))
            print(f"{pc_s}: status={v.status}  locals={{ {locs} }}  stack={stack}  heap={{ {heap_s} }}")

            if v.status != "ok":
                final_status = v.status

    print(final_status)

if __name__ == "__main__":
    methodid, input = jpamb.getcase()
    
    # Abstract run
    abstract_seen = execute_A(methodid, input)
    #print("== abstract ==")
    dump_A(abstract_seen)

