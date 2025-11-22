import jpamb
from jpamb import jvm
from dataclasses import dataclass
import numpy
import virtual_methods
import dynamic_methods
from sqlite import query

import sys
from loguru import logger

from SignSet import SignSet, TOP, BOT
from LengthAbstraction import LenInterval
AValue = SignSet
from typing import Generic, TypeVar
T = TypeVar("T")

logger.remove()
logger.add(sys.stderr, format="[{level}] {message}")

@dataclass
class PC:
    method: jvm.AbsMethodID
    offset: int

    def __iadd__(self, delta):
        self.offset += delta
        return self

    def __add__(self, delta):
        return PC(self.method, self.offset + delta)
    
    def replace(self, val):
        self.offset = val

    def __str__(self):
        return f"{self.method}:{self.offset}"


@dataclass
class Bytecode:
    suite: jpamb.Suite
    methods: dict[jvm.AbsMethodID, list[jvm.Opcode]]

    def __getitem__(self, pc: PC) -> jvm.Opcode:
        try:
            opcodes = self.methods[pc.method]
        except KeyError:
            opcodes = list(self.suite.method_opcodes(pc.method))
            self.methods[pc.method] = opcodes

        return opcodes[pc.offset]


@dataclass
class Stack(Generic[T]):
    items: list[T]

    def __bool__(self) -> bool:
        return len(self.items) > 0

    @classmethod
    def empty(cls):
        return cls([])

    def peek(self) -> T:
        return self.items[-1]

    def pop(self) -> T:
        return self.items.pop(-1)

    def push(self, value):
        self.items.append(value)
        return self

    def __str__(self):
        if not self:
            return "ϵ"
        return "".join(f"{v}" for v in self.items)


suite = jpamb.Suite()
bc = Bytecode(suite, dict())


@dataclass
class Frame:
    locals: dict[int, jvm.Value]
    stack: Stack[jvm.Value]
    pc: PC

    def __str__(self):
        locals = ", ".join(f"{k}:{v}" for k, v in sorted(self.locals.items()))
        return f"<{{{locals}}}, {self.stack}, {self.pc}>"
    
    @staticmethod
    def from_method(method: jvm.AbsMethodID) -> "Frame":
        return Frame({}, Stack.empty(), PC(method, 0))


@dataclass
class State:
    heap: dict[int, jvm.Value]
    heap_items: int
    frames: Stack[Frame]

    def heap_append(self, val):
        self.heap[self.heap_items] = val
        idx = self.heap_items
        self.heap_items += 1
        return idx

    def __str__(self):
        return f"{self.heap} {self.frames}"
    
#### Abstract stuff ####
    
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



def step(state: State) -> State | str:
    assert isinstance(state, State), f"expected frame but got {state}"
    frame = state.frames.peek()
    opr = bc[frame.pc]
    logger.debug(f"STEP {opr}\n{state}")
    match opr:
        case jvm.Push(value=v):
            match v.type:
                case jvm.Reference():
                    idx = state.heap_append(v.value)
                    frame.stack.push(jvm.Value.reference(idx))
                case _:
                    frame.stack.push(v)

            frame.pc += 1
            return state
        case jvm.Load(type=type, index=idx):
            local = frame.locals[idx]
            assert local.type == type, f"Expected type {type}, got {local.type}"
            frame.stack.push(local)
            frame.pc += 1
            return state
        case jvm.ArrayLoad(type=type):
            idx, ref = frame.stack.pop(), frame.stack.pop()
            arr = state.heap[ref.value]

            if arr == None:
                return "null pointer"

            assert arr.type.contains == type, f"Expected type {type}, got {arr.type.contains}"

            if len(arr.value) <= idx.value:
                return "out of bounds"

            frame.stack.push(jvm.Value.int(arr.value[idx.value]))
            frame.pc += 1
            return state
        case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Div):
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            assert v1.type is jvm.Int(), f"expected int, but got {v1}"
            assert v2.type is jvm.Int(), f"expected int, but got {v2}"
            if v2.value == 0:
                return "divide by zero"

            frame.stack.push(jvm.Value.int(v1.value // v2.value))
            frame.pc += 1
            return state
        case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Sub):
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            assert v1.type is jvm.Int(), f"expected int, but got {v1}"
            assert v2.type is jvm.Int(), f"expected int, but got {v2}"
            frame.stack.push(jvm.Value.int(v1.value - v2.value))
            frame.pc += 1
            return state
        case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Rem):
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            assert v1.type is jvm.Int(), f"expected int, but got {v1}"
            assert v2.type is jvm.Int(), f"expected int, but got {v2}"
            frame.stack.push(jvm.Value.int(v1.value % v2.value))
            frame.pc += 1
            return state
        case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Mul):
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            assert v1.type is jvm.Int(), f"expected int, but got {v1}"
            assert v2.type is jvm.Int(), f"expected int, but got {v2}"
            frame.stack.push(jvm.Value.int(v1.value * v2.value))
            frame.pc += 1
            return state
        case jvm.Binary(type=jvm.Int(), operant=jvm.BinaryOpr.Add):
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            assert v1.type is jvm.Int(), f"expected int, but got {v1}"
            assert v2.type is jvm.Int(), f"expected int, but got {v2}"
            frame.stack.push(jvm.Value.int(v1.value + v2.value))
            frame.pc += 1
            return state
        case jvm.Return(type=None):
            v1 = state.frames.pop()
            if state.frames:
                return state
            else:
                return "ok"
        case jvm.Return(type=type):
            v1 = frame.stack.pop()
            assert v1.type == type, f"Expected {type}, got {v1.type}"
            state.frames.pop()
            if state.frames:
                frame = state.frames.peek()
                frame.stack.push(v1)
                return state
            else:
                return "ok"
        case jvm.Dup():
            v1 = frame.stack.peek()
            frame.stack.push(v1)
            frame.pc += 1
            return state
        case jvm.Get(field=field, static=static):
            if field.extension.name == "$assertionsDisabled":
                frame.stack.push(jvm.Value.int(0))
                frame.pc += 1
                return state
            else:
                raise NotImplementedError(f"Don't know how to handle get that is not $assertionsDisabled: {field!r}")
        case jvm.Ifz(condition=condition, target=target) | jvm.If(condition=condition, target=target):
            v2 = 0 if isinstance(opr, jvm.Ifz) else frame.stack.pop().value
            v1 = frame.stack.pop()
            match condition:
                case "ne":
                    if v1.value != v2:
                        frame.pc.replace(target)
                    else:
                        frame.pc += 1
                case "eq":
                    if v1.value == v2:
                        frame.pc.replace(target)
                    else:
                        frame.pc += 1
                case "gt":
                    if v1.value > v2:
                        frame.pc.replace(target)
                    else:
                        frame.pc += 1
                case "lt":
                    if v1.value < v2:
                        frame.pc.replace(target)
                    else:
                        frame.pc += 1
                case "ge":
                    if v1.value >= v2:
                        frame.pc.replace(target)
                    else:
                        frame.pc += 1
                case "le":
                    if v1.value <= v2:
                        frame.pc.replace(target)
                    else:
                        frame.pc += 1
                case _:
                    raise NotImplementedError(f"Don't know how to handle condition of type: {condition!r}")
            return state
        case jvm.New(classname=cname):
            idx = state.heap_append(cname.name)
            frame.stack.push(jvm.Value.reference(idx))
            frame.pc += 1
            return state
        case jvm.InvokeSpecial(method=m, is_interface=is_interface):
            if len(m.extension.params) == 0:
                v1 = frame.stack.pop()
                frame.pc += 1
                return state
            raise NotImplementedError("Don't know how to handle special invocations with more than 0 elements")
        case jvm.InvokeStatic(method=m):
            new_frame = Frame.from_method(m)
            
            args = [frame.stack.pop() for _ in range(len(m.extension.params))][-1:] # pop all arguments and reverse to get the right order

            if "sink" in m.extension.name:
                # get first (and only) argument
                arg = args[0]
                # execute sqlite query on interpreter side
                query_result = query(state.heap[arg.value])

                if query_result and "5tr0ngP@55w0rd!" in query_result:
                    return "vulnerable"

            for i, v in enumerate(args):
                match v:
                    case jvm.Value(type=jvm.Boolean(), value=value):
                        v = jvm.Value.int(1 if value else 0)
                    case jvm.Value(type=jvm.Char(), value=value):
                        v = jvm.Value.int(ord(value))
                    case jvm.Value(type=jvm.Int(), value=value) | jvm.Value(jvm.Float(), value=value) | jvm.Value(jvm.Double(), value=value):
                        pass
                    case jvm.Value(type=jvm.Array(), value=value):
                        
                        match v.type.contains:
                            case jvm.Char():
                                value = [ord(x) for x in value]
                            case jvm.Int():
                                pass
                            case _:
                                raise NotImplementedError(f"Don't know how to handle arrays of type {v.type.contains} passed as input")

                        idx = state.heap_append(jvm.Value.array(v.type.contains, value))
                        v = jvm.Value.reference(idx)
                    case jvm.Value(type=jvm.Reference(), value=value):
                        pass
                    case _:
                        raise NotImplementedError(f"Don't know how to handle {v}")
                new_frame.locals[i] = v

            frame.pc += 1
            state.frames.push(new_frame)
            return state
        case jvm.InvokeVirtual(method=m):
            match m.classname.name:
                case "java/lang/String":
                    match m.extension.name:
                        case "length":
                            ref = frame.stack.pop()
                            assert ref.type == jvm.Reference(), f"Expected reference, got {ref.type}"
                            v = state.heap[ref.value]
                            result = jvm.Value.int(virtual_methods.stringLength(v))
                            frame.pc += 1
                            frame.stack.push(result)
                            return state
                        case "charAt":
                            index = frame.stack.pop()
                            assert index.type == jvm.Int(), f"Expected int, got {index.type}"
                            ref = frame.stack.pop()
                            assert ref.type == jvm.Reference(), f"Expected reference, got {ref.type}"
                            v = state.heap[ref.value]
                            result = virtual_methods.stringCharAt(v, index.value)
                            if result == "StringIndexOutOfBoundsException":
                                return "out of bounds"
                            frame.pc += 1
                            frame.stack.push(jvm.Value.char(result))
                            return state
                        case "equals":
                            ref2 = frame.stack.pop()
                            assert ref2.type == jvm.Reference(), f"Expected reference, got {ref2.type}"
                            v2 = state.heap[ref2.value]
                            ref1 = frame.stack.pop()
                            assert ref1.type == jvm.Reference(), f"Expected reference, got {ref1.type}"
                            v1 = state.heap[ref1.value]
                            result = jvm.Value.int(1 if virtual_methods.stringEquals(v1, v2) else 0)
                            frame.pc += 1
                            frame.stack.push(result)
                            return state
                        case "substring":
                            if len(m.extension.params) == 1:
                                val = frame.stack.pop()
                                assert val.type == jvm.Int(), f"Expected integer, got {val.type}"
                                ref = frame.stack.pop()
                                assert ref.type == jvm.Reference(), f"Expected reference, got {ref.type}"
                                s = state.heap[ref.value]
                                result = virtual_methods.stringSubstring(s, val.value)
                            else:
                                higher = frame.stack.pop()
                                assert higher.type == jvm.Int(), f"Expected integer, got {higher.type}"
                                lower = frame.stack.pop()
                                assert lower.type == jvm.Int(), f"Expected integer, got {lower.type}"
                                ref = frame.stack.pop()
                                assert ref.type == jvm.Reference(), f"Expected reference, got {ref.type}"
                                s = state.heap[ref.value]
                                result = virtual_methods.stringSubstring(s, lower.value, higher.value)
                            
                            if result == "StringIndexOutOfBoundsException":
                                return "out of bounds"

                            idx = state.heap_append(result)

                            frame.pc += 1
                            frame.stack.push(jvm.Value.reference(idx))
                            return state

                        case "indexOf":
                            target = frame.stack.pop()

                            match target.type:
                                case jvm.Reference():
                                    target = state.heap[target.value]
                                case jvm.Int():
                                    target = chr(target.value)
                                case t:
                                    assert False, f"Expected reference or int, got {t}"

                            source = frame.stack.pop()
                            assert source.type == jvm.Reference(), f"Expected reference, got {source.type}"
                            source = state.heap[source.value]

                            result = jvm.Value.int(virtual_methods.stringIndexOf(source, target))

                            frame.pc += 1
                            frame.stack.push(result)
                            return state

                        case name:
                            raise NotImplementedError(f"Don't know how to handle String method \"{name}\"")
                case c:
                    raise NotImplementedError(f"Don't know how to handle invokevirtual of classname \"{c}\"")
        case jvm.InvokeDynamic(method=m):
            # NOTE: this is very hacky

            # find bootstrap entry in the class that contains the currently executing method
            cls_json = suite.findclass(frame.pc.method.classname) 
            bm = cls_json["bootstrapmethods"][opr.index]

            match m.classname.name:
                case "makeConcatWithConstants":
                    args = [frame.stack.pop() for _ in range(len(m.extension.params))][::-1]  # pop all arguments and reverse to get the right order
                    
                    # TODO: handle non-reference types
                    args = [state.heap[arg.value] for arg in args]

                    recipe = bm["method"]["args"][0]["value"]

                    # TODO: makeConcatWithConstants should probably have access to the jvm types in some format
                    # whether that being jvm.Type or having the args as tuples of (type_repr, value)
                    # because python e.g. does not distinguish between integer types like JVM does
                    result = dynamic_methods.makeConcatWithConstants(recipe, args)
                    idx = state.heap_append(result)
                    frame.stack.push(jvm.Value.reference(idx))
                    frame.pc += 1
                    return state                    
                case c:
                    raise NotImplementedError(f"Don't know how to handle invokedynamic of classname \"{c}\"")

        case jvm.Throw():
            v1 = frame.stack.pop()
            if state.heap[v1.value] == "java/lang/AssertionError":
                return 'assertion error'
            else:
                raise NotImplementedError(f"Don't know how to handle non-assertion error error: {state.heap[v1]!r}")
        case jvm.Store(type=type, index=idx):
            v = frame.stack.pop()
            assert v.type == type, f"Expected type {type}, got {v.type}"
            frame.locals[idx] = v
            frame.pc += 1
            return state
        case jvm.ArrayStore(type=jvm.Int()):
            v, idx, ref = frame.stack.pop(), frame.stack.pop(), frame.stack.pop()
            assert ref.type == jvm.Reference(), f"Expected reference, got {ref.type}"
            assert idx.type == jvm.Int(), f"Expected integer, got {idx.type}"

            if ref.value == None:
                return "null pointer"

            arr = state.heap[ref.value]

            if arr == None:
                return "null pointer"
            
            assert v.type == arr.type.contains, f"Expected {arr.type}, got {v.type}"
            if len(arr.value) <= idx.value:
                return "out of bounds"

            # Array content is stored as tuple (immutable) and array.value is frozen (immutable)
            # so we need to overwrite the whole content in the heap
            new_content = list(arr.value)
            new_content[idx.value] = v.value
            state.heap[ref.value] = jvm.Value.array(v.type, new_content)

            frame.pc += 1
            return state
        case jvm.Goto(target=target):
            frame.pc.replace(target)
            return state
        case jvm.Cast(from_=from_, to_=to_):
            v = frame.stack.pop()
            assert v.type == from_, f"Expected type {from_}, got {v.type}"
            match to_:
                case jvm.Short():
                        frame.stack.push(jvm.Value.int(numpy.short(v.value))) 
                case _:
                    raise NotImplementedError(f"Don't know how to cast to: {to_}")
            frame.pc += 1
            return state
        case jvm.NewArray(type=type, dim=dim):
            v = frame.stack.pop()
            assert v.type == jvm.Int(), f"Expected operand to be of type int, got {v.type}"
            match type:
                case jvm.Int():
                    heap_pos = state.heap_append(jvm.Value.array(type, [0 for _ in range(v.value)]))
                    frame.stack.push(jvm.Value.reference(heap_pos))
                case t:
                    raise NotImplementedError(f"Don't know how to handle arrays of type {t}")
            frame.pc += 1
            return state
        case jvm.ArrayLength():
            ref = frame.stack.pop()

            assert ref.type == jvm.Reference(), f"Expected reference got {ref.type}"
            
            if ref.value == None:
                return "null pointer"
            
            arr = state.heap[ref.value]

            if arr == None:
                return "null pointer"

            frame.stack.push(jvm.Value.int(len(arr.value)))

            frame.pc += 1
            return state
        case jvm.Incr(index=idx, amount=amount):
            assert frame.locals[idx].type == jvm.Int(), f"Expected {jvm.Int()}, got {frame.locals[idx].type}"
            frame.locals[idx] = jvm.Value.int(frame.locals[idx].value + amount)
            frame.pc += 1
            return state
        case a:
            raise NotImplementedError(f"Don't know how to handle: {a!r}")

def execute(methodid, input):
    frame = Frame.from_method(methodid)
    heap = {}
    heap_items = 0
    for i, v in enumerate(input.values):
        match v:
            case jvm.Value(type=jvm.Boolean(), value=value):
                v = jvm.Value.int(1 if value else 0)
            case jvm.Value(type=jvm.Char(), value=value):
                v = jvm.Value.int(ord(value))
            case jvm.Value(type=jvm.Int(), value=value) | jvm.Value(jvm.Float(), value=value) | jvm.Value(jvm.Double(), value=value):
                pass
            case jvm.Value(type=jvm.Array(), value=value):
                
                match v.type.contains:
                    case jvm.Char():
                        value = [ord(x) for x in value]
                    case jvm.Int():
                        pass
                    case _:
                        raise NotImplementedError(f"Don't know how to handle arrays of type {v.type.contains} passed as input")

                heap[heap_items] = jvm.Value.array(v.type.contains, value)
                idx = heap_items
                heap_items += 1
                v = jvm.Value.reference(idx)
            case jvm.Value(type=jvm.Object(name), value=value):
                if name.name != "java/lang/String":
                    raise NotImplementedError("Don't know how to handle objects of name {name.name}")
               
                value = value[1:-1]  # Strings keep their quotations marks from parser
                heap[heap_items] = value
                idx = heap_items
                heap_items += 1
                v = jvm.Value.reference(idx)
            case _:
                raise NotImplementedError(f"Don't know how to handle {v}")
        frame.locals[i] = v
    state = State(heap, heap_items, Stack.empty().push(frame))

    for x in range(1000000):
        state = step(state)
        if isinstance(state, str):
            return state
    else:
        logger.debug("No more steps")
        return "*"
    
# abstract stuff

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
    # Concrete run
    #concrete = execute(methodid, input)
    #print(concrete)

    # Abstract run
    abstract_seen = execute_A(methodid, input)
    #print("== abstract ==")
    dump_A(abstract_seen)
    