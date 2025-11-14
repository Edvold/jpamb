def makeConcatWithConstants(recipe, constants):
    types = {}
    for const in constants:
        types.setdefault(type(const), []).append(const)
    
    types_list = list(types.keys())

    result = []
    for char in recipe:
        encoding = ord(char)
        if 1 <= encoding <= 31:
            result.append(str(types[types_list[encoding-1]].pop(0)))
        else:
            result.append(char)
    return ''.join(result)