from __future__ import annotations
from dataclasses import dataclass

_NEG, _ZERO, _POS = 1, 2, 4

@dataclass(frozen=True)
class SignSet:
    mask: int

    @staticmethod
    def neg() -> "SignSet":  return SignSet(_NEG)
    @staticmethod
    def zero() -> "SignSet": return SignSet(_ZERO)
    @staticmethod
    def pos() -> "SignSet":  return SignSet(_POS)
    @staticmethod
    def bot() -> "SignSet":  return SignSet(0)
    @staticmethod
    def top() -> "SignSet":  return SignSet(_NEG | _ZERO | _POS)

    def __add__(self, other: "SignSet") -> "SignSet":  return self.add(other)
    def __sub__(self, other: "SignSet") -> "SignSet":  return self.sub(other)
    def __mul__(self, other: "SignSet") -> "SignSet":  return self.mul(other)
    def __le__(self, other: "SignSet") -> bool:        return self.le(other)


    @staticmethod
    def of_int(v: int) -> "SignSet":
        if v < 0: return SignSet.neg()
        if v > 0: return SignSet.pos()
        return SignSet.zero()

    def __str__(self) -> str:
        if self.mask == 0: return "⊥"
        if self.mask == (_NEG | _ZERO | _POS): return "⊤"
        parts = []
        if self.mask & _NEG:  parts.append("−")
        if self.mask & _ZERO: parts.append("0")
        if self.mask & _POS:  parts.append("+")
        return "{" + ",".join(parts) + "}"

    
    def __or__(self, other: "SignSet") -> "SignSet":  
        return SignSet(self.mask | other.mask)
    
    ### needed for hypothesis testing, can be potentially removed
    
    @staticmethod
    def _mask_of_int(v: int) -> int:
        return _NEG if v < 0 else _POS if v > 0 else _ZERO

    @classmethod
    def abstract(cls, items: set[int]) -> "SignSet":
        m = 0
        for v in items:
            m |= cls._mask_of_int(v)
        return cls(m)
    
    ###

    ### helpers
    @property
    def signs(self) -> bool:
        return self.mask != 0

    def may_be_zero(self) -> bool:
        return (self.mask & _ZERO) != 0

    def may_be_nonzero(self) -> bool:
        return (self.mask & (_NEG | _POS)) != 0

    def may_be_neg(self) -> bool:
        return (self.mask & _NEG) != 0

    def may_be_pos(self) -> bool:
        return (self.mask & _POS) != 0

    def _from_flags(self, neg: bool, zero: bool, pos: bool) -> "SignSet":
        m = ( _NEG if neg else 0 ) | ( _ZERO if zero else 0 ) | ( _POS if pos else 0 )
        return SignSet(m)
    
    ### abstract arithmetic

    def add(self, b: "SignSet") -> "SignSet":
        a = self

        neg = a.may_be_neg() or b.may_be_neg()
        
        pos = a.may_be_pos() or b.may_be_pos()
        
        zero = a.may_be_zero() or b.may_be_zero() or \
               (a.may_be_neg() and b.may_be_pos()) or \
               (a.may_be_pos() and b.may_be_neg())
        
        return self._from_flags(neg, zero, pos)

    def sub(self, b: "SignSet") -> "SignSet":
        return self.add(b.negate())

    def mul(self, b: "SignSet") -> "SignSet":
        a = self
        zero = a.may_be_zero() or b.may_be_zero()
        neg = (a.may_be_neg() and b.may_be_pos()) or (a.may_be_pos() and b.may_be_neg())
        pos = (a.may_be_pos() and b.may_be_pos()) or (a.may_be_neg() and b.may_be_neg())
        return self._from_flags(neg, zero, pos)
    
    def le(self, other: "SignSet") -> bool:
        return (
            (self.mask & other.mask) == self.mask 
            or ((self.may_be_neg() or self.may_be_zero()) and (not other.may_be_neg() and (other.may_be_pos() or other.may_be_zero())))
            ) 

    def div(self, b: "SignSet") -> tuple["SignSet", bool]:
        a = self
        dz = b.may_be_zero()
        B_nz = b.mask & (_NEG | _POS)
        if B_nz == 0:
            return (SignSet.bot(), dz)
        neg = (a.may_be_neg() and (B_nz & _POS)) or (a.may_be_pos() and (B_nz & _NEG))
        pos = (a.may_be_pos() and (B_nz & _POS)) or (a.may_be_neg() and (B_nz & _NEG))
        zero = a.may_be_zero()                     # ← only this
        return (self._from_flags(bool(neg), bool(zero), bool(pos)), dz)


    def rem(self, b: "SignSet") -> tuple["SignSet", bool]:
        a = self
        dz = b.may_be_zero()
        if not b.may_be_nonzero():
            return (SignSet.bot(), dz)
        neg = a.may_be_neg()
        pos = a.may_be_pos()
        zero = not a.is_bot()                     
        return (self._from_flags(neg, zero, pos), dz)

    def negate(self) -> "SignSet":
        neg = self.may_be_pos()
        pos = self.may_be_neg()
        zero = self.may_be_zero()
        return self._from_flags(neg, zero, pos)
    
    def is_bot(self) -> bool: return self.mask == 0

BOT = SignSet.bot()
TOP = SignSet.top()
NEG = SignSet.neg()
ZERO = SignSet.zero()
POS = SignSet.pos()
