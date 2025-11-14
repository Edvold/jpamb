def stringLength(s: str):
    return len(s)

def stringCharAt(s: str, index: int):
    if index < 0 or index >= len(s):
        return "StringIndexOutOfBoundsException"
    return s[index]

def stringEquals(s1: str, s2: str):
    return s1 == s2

def stringSubstring(s: str, lower: int, higher: int = None):
    if higher == None:
        higher = len(s)
    
    if lower < 0 or lower > higher or higher < 0 or higher > len(s):
        return "StringIndexOutOfBoundsException"
    
    return s[lower:higher]

def stringIndexOf(source: str, target: str):
    try:
        return source.index(target)
    except:
        return -1