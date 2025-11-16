from __future__ import annotations
from enum import Enum, auto
from dataclasses import dataclass

class TaintValue(Enum):
    SAFE = auto()
    TAINTED = auto()
    UNKNOWN = auto()
    BOT = auto()

@dataclass(frozen = True)
class TaintSet:
    
    taint: TaintValue

    @staticmethod
    def safe() -> TaintSet: return TaintSet(TaintValue.SAFE)
    @staticmethod
    def tainted() -> TaintSet: return TaintSet(TaintValue.TAINTED)
    @staticmethod
    def unknown() -> TaintSet: return TaintSet(TaintValue.UNKNOWN)
    @staticmethod
    def bot() -> TaintSet: return TaintSet(TaintValue.BOT)

    def __add__(self, other: TaintSet) -> TaintSet:
        if self.taint == TaintValue.TAINTED or other.taint == TaintValue.TAINTED:
            return TaintSet.tainted()
        if self.taint == TaintValue.UNKNOWN or other.taint == TaintValue.UNKNOWN:
            return TaintSet.unknown()
        return TaintSet.safe()
    
    def is_safe(self) -> bool:
        return self.taint == TaintValue.SAFE
    
    def is_tainted(self) -> bool:
        return self.taint == TaintValue.TAINTED
    
    def may_be_tainted(self) -> bool:
        return self.taint == TaintValue.UNKNOWN

    def __str__(self) -> str:
        match self.taint:
            case TaintValue.BOT:
                return "⊥"
            case TaintValue.SAFE:
                return "safe"
            case TaintValue.TAINTED:
                return "tainted"
            case TaintValue.UNKNOWN:
                return "unknown"