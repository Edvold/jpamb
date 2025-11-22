from dataclasses import dataclass


INF = 10**12 

@dataclass(frozen=True)
class LenInterval:
    lo: int
    hi: int  

    def __str__(self):
        h = "∞" if self.hi >= INF else str(self.hi)
        return f"[{self.lo}, {h}]"

    @staticmethod
    def const(n: int) -> "LenInterval":
        return LenInterval(n, n)

    @staticmethod
    def top() -> "LenInterval":
        return LenInterval(0, INF)

    def join(self, other: "LenInterval") -> "LenInterval":
        return LenInterval(min(self.lo, other.lo), max(self.hi, other.hi))

    def add_const(self, k: int) -> "LenInterval":
        lo = max(0, self.lo + k)  
        hi = INF if self.hi >= INF else self.hi + k
        return LenInterval(lo, hi)
    
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