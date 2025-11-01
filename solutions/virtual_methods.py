def stringLength(s):
    return len(s)

def stringCharAt(s, index):
    if index < 0 or index >= len(s):
        return "StringIndexOutOfBoundsException"
    return s[index]

def stringEquals(s1, s2):
    return s1 == s2