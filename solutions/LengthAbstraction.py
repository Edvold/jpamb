from dataclasses import dataclass


@dataclass(frozen=True)
class LenInterval:
    lo: int
    hi: int  

    INF_VAL = 10**12
    NEG_INF_VAL = -10**12

    def __str__(self):
        l = "-∞" if self.lo <= self.NEG_INF_VAL else str(self.lo)
        h = "∞" if self.hi >= self.INF_VAL else str(self.hi)
        return f"[{l}, {h}]"

    @staticmethod
    def const(n: int) -> "LenInterval":
        return LenInterval(n, n)
    
    def _clamped_lo(self, n: int) -> int:
        return n

    @staticmethod
    def top() -> "LenInterval":
        return LenInterval(LenInterval.NEG_INF_VAL, LenInterval.INF_VAL)

    def join(self, other: "LenInterval") -> "LenInterval":
        return LenInterval(min(self.lo, other.lo), max(self.hi, other.hi))
    
    def __or__(self, other: "LenInterval") -> "LenInterval":
        return self.join(other)
    
    def meet(self, other: "LenInterval") -> "LenInterval":
        new_lo = max(self.lo, other.lo)
        new_hi = min(self.hi, other.hi)
        if new_lo > new_hi:
            return LenInterval(1, 0) 
        return LenInterval(new_lo, new_hi)

    def is_empty(self) -> bool:
        return self.lo > self.hi

    def add(self, other: "LenInterval") -> "LenInterval":
        if self.lo <= self.NEG_INF_VAL or other.lo <= self.NEG_INF_VAL:
            new_lo = self.NEG_INF_VAL
        else:
            new_lo = self.lo + other.lo
            
        if self.hi >= self.INF_VAL or other.hi >= self.INF_VAL:
            new_hi = self.INF_VAL
        else:
            new_hi = self.hi + other.hi
        
        return LenInterval(new_lo, new_hi)

    def sub(self, other: "LenInterval") -> "LenInterval":
        if self.lo <= self.NEG_INF_VAL or other.hi >= self.INF_VAL:
            new_lo = self.NEG_INF_VAL
        else:
            new_lo = self.lo - other.hi
            
        if self.hi >= self.INF_VAL or other.lo <= self.NEG_INF_VAL:
            new_hi = self.INF_VAL
        else:
            new_hi = self.hi - other.lo
            
        return LenInterval(new_lo, new_hi)

    def widening(self, other: "LenInterval") -> "LenInterval":
        thresholds = [-1, 0, 1, 5, 10, 100, 1000] 

        if other.lo < self.lo:
            new_lo = self.NEG_INF_VAL
            for t in reversed(thresholds):
                if t <= other.lo:
                    new_lo = t
                    break
        else:
            new_lo = self.lo 

        if other.hi > self.hi:
            new_hi = self.INF_VAL
            for t in thresholds:
                if t >= other.hi:
                    new_hi = t
                    break
        else:
            new_hi = self.hi

        return LenInterval(new_lo, new_hi)

    def mul(self, other: "LenInterval") -> "LenInterval":
        bounds = [
            self.lo * other.lo, 
            self.lo * other.hi, 
            self.hi * other.lo, 
            self.hi * other.hi
        ]
    
        if any(b >= self.INF_VAL for b in bounds):
             new_hi = self.INF_VAL
        else:
             new_hi = max(bounds)

        min_b = min(bounds)
        if min_b <= self.NEG_INF_VAL:
            new_lo = self.NEG_INF_VAL
        else:
            new_lo = self._clamped_lo(min_b)
        
        return LenInterval(new_lo, max(new_lo, new_hi))
    
    def div(self, other: "LenInterval") -> tuple["LenInterval", bool]:
        if other.lo <= 0 <= other.hi:
            return LenInterval.top(), True 

        def calc_bound(val1, val2):
            return int(val1 / val2) 
            
        bounds = [
            calc_bound(self.lo, other.lo),
            calc_bound(self.lo, other.hi),
            calc_bound(self.hi, other.lo),
            calc_bound(self.hi, other.hi)
        ]
        
        new_lo = max(self.NEG_INF_VAL, min(bounds))
        new_hi = min(self.INF_VAL, max(bounds))
        
        return LenInterval(new_lo, new_hi), False
    
    
    def may_contain_index(self, idx_min: int, idx_max: int) -> tuple[bool, bool]:

        l_min = self.lo
        l_max = self.hi

        if idx_max < 0:
            may_in = False
        else:
            nn_min = max(idx_min, 0)
            nn_max = idx_max
            if nn_min > nn_max:
                may_in = False
            else:
                may_in = (l_max > nn_min)
                
        may_oob = (idx_min < 0) or (idx_max >= l_min)

        return (may_in, may_oob)