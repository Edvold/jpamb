#!/usr/bin/env python3
import sys
import re
from interpreter import *
from taint_analysis import is_method_tainted
from abstract_interpreter import abstract_taint_res
#from interpreter import current_pc_value
import jpamb
import random
from loguru import logger
import tree_sitter
import tree_sitter_java

def dynamic_analysis(methodid):

    # various setup stuff
    java_max_int = 2**32-1
    java_min_int = -2**32
    int_test_vals = {"-1", "0", "1"}
    char_test_vals = {"' '"}
    string_test_vals = {"\"\"", "\"\""}


    JAVA_LANGUAGE = tree_sitter.Language(tree_sitter_java.language())
    parser = tree_sitter.Parser(JAVA_LANGUAGE)

    # Actual analysis beginning here
    srcfile = jpamb.sourcefile(methodid)

    with open(srcfile, "rb") as f:
        tree = parser.parse(f.read())

    simple_classname = str(methodid.classname.name)
    
    class_q = tree_sitter.Query(JAVA_LANGUAGE,
        f"""
        (class_declaration 
            name: ((identifier) @class-name 
                (#eq? @class-name "{simple_classname}"))) @class
    """
    )

    for node in tree_sitter.QueryCursor(class_q).captures(tree.root_node)["class"]:
        break
    else:
        #could not find class with name {simple_classname}
        sys.exit(-1)

    method_name = methodid.extension.name

    method_q = tree_sitter.Query(JAVA_LANGUAGE,
        f"""
        (method_declaration name: 
        ((identifier) @method-name (#eq? @method-name "{method_name}"))
        ) @method
    """
    )

    for node in tree_sitter.QueryCursor(method_q).captures(node)["method"]:
        body = node.child_by_field_name("body")
        method_body = body.text.decode()
        numbers_in_body = re.findall(r"\d+", method_body)
        chars_in_body = re.findall(r"('.')", method_body)
        string_in_body = re.findall(r"(\".*?\")", method_body)
        for n in numbers_in_body:
            int_test_vals.add(n)
        for c in chars_in_body:
            char_test_vals.add(c)
        for s in string_in_body:
            string_test_vals.add(s)
            

    # Make predictions (improve these by looking at the Java code!)
    ok_chance = "50%"
    divide_by_zero_chance = "50%"
    assertion_error_chance = "50%"
    out_of_bounds_chance = "50%"
    null_pointer_chance = "50%"
    infinite_loop_chance = "50%"
    vulnerable = "50%"
    #completed_interpreter_classes = ["jpamb.cases.Simple", "jpamb.cases.Tricky", "jpamb.cases.Loops", "jpamb.cases.Calls", "jpamb.cases.Arrays", "jpamb.cases.Strings", "jpamb.cases.Vulnerable"]

    #if classname in completed_interpreter_classes:

    states = set()
    int_test_vals = list(int_test_vals)
    bool_test_vals = ["true", "false"]
    for string in string_test_vals:
        if 'db' in string:
            string_test_vals.add("\"john\"")
            string_test_vals.add("\"password\"")
            string_test_vals.add("\"admin\' OR 1=1; -- \"")
            break
    string_test_vals = list(string_test_vals)
    char_test_vals = list(char_test_vals)
    array_input = False

    fuzzing_tests = 0

    if args.startswith("()"):
        input = jpamb.parse_input("()")
        logger.disable("interpreter")
        state = execute(methodid, input)
        logger.enable("interpreter")
        states.add(state)
    else:
        arg_types = list(args)[1:-2]
        fixed_arg_types = []
        #logger.debug(len(arg_types))
        i = 0
        while i < len(arg_types):
            arg_type = ''
            if arg_types[i] == "[": #array argument
                arg_type = arg_types[i] + arg_types[i+1]
                i += 1
            elif arg_types[i] == "L": #Object
                last_index = arg_types.index(";", i)
                arg_type = "".join(arg_types[i:last_index+1])
                i = last_index
            else:
                arg_type = arg_types[i]
            fixed_arg_types.append(arg_type)
            i += 1
        itv_mult_val = 0
        btv_mult_val = 0
        ctv_mult_val = 0
        stv_mult_val = 0
        if "I" in fixed_arg_types:
            max_len = 0
            for s in string_test_vals:
                if len(s) > max_len:
                    max_len = len(s)
            additional_ints = [str(i) for i in range(0, min(20, max_len))]
            for ai in additional_ints:
                if ai not in int_test_vals:
                    int_test_vals.append(ai) 
            itv_mult_val = len(int_test_vals) 
        else: itv_mult_val = 1
        if "Z" in fixed_arg_types:
            btv_mult_val = len(bool_test_vals) 
        else: btv_mult_val = 1
        if "C" in fixed_arg_types:
            ctv_mult_val = len(char_test_vals) 
        else: ctv_mult_val = 1
        if "Ljava/lang/String;" in fixed_arg_types:
            stv_mult_val = len(string_test_vals)                    
        else: stv_mult_val = 1
        #check if the type variables exist then var = len(set) else = 1
        for index in range((itv_mult_val*btv_mult_val*ctv_mult_val*stv_mult_val) ** len(fixed_arg_types)):#len(int_test_vals)*len(bool_test_vals)*len(char_test_vals)*len(string_test_vals)):
            arg_values = []
            arr_values = []
            fixed_arg_index = index
            for a in fixed_arg_types:
                match a:
                    case "I":
                        arg_values.append(str(int_test_vals[fixed_arg_index % len(int_test_vals)]))
                    case "Z":
                        arg_values.append(str(bool_test_vals[fixed_arg_index % len(bool_test_vals)]))
                    case "Ljava/lang/String;":
                        arg_values.append(str(string_test_vals[fixed_arg_index % len(string_test_vals)]))
                    case "C":
                        #NOBODY USES THIS SHIT PLEASE
                        arg_values.append(str(char_test_vals[fixed_arg_index % len(char_test_vals)]))
                    case "[C":  # char array
                        #array_input = True
                        #brea
                        if array_input:
                            continue
                        array_val = "([C:"
                        pc_vals = [get_pc_value()]
                        #logger.debug(pc_vals)
                        #logger.debug(char_test_vals)
                        for char in char_test_vals:
                            set_pc_value(0)
                            #logger.debug(f"The pc at the start is: {get_pc_value()}")
                            test_array_val = array_val + char + "])"
                            input = jpamb.parse_input(test_array_val)
                            #logger.debug(input)
                            logger.disable("interpreter")
                            execute(methodid, input)
                            logger.enable("interpreter")
                            #logger.debug(f"The current pc value is: {get_pc_value()}")
                            if not get_pc_value() in pc_vals:
                                arr_values.append(test_array_val)
                                pc_vals.append(get_pc_value()) 
                        #logger.debug(pc_vals)
                        #logger.debug(arg_values)
                        fixed = False
                        while not fixed:
                            arr_val_length = len(arr_values)
                            for arr_val in arr_values:
                                #logger.debug(arg_val)
                                array_val = arr_val[0:-2] + ","
                                for char in char_test_vals:
                                    set_pc_value(0)
                                    #logger.debug(f"The pc at the start is: {get_pc_value()}")
                                    test_array_val = array_val + char + "])"
                                    input = jpamb.parse_input(test_array_val)
                                    #logger.debug(input)
                                    logger.disable("interpreter")
                                    execute(methodid, input)
                                    logger.enable("interpreter")
                                    #logger.debug(f"The current pc value is: {get_pc_value()}")
                                    #logger.debug(not get_pc_value() in pc_vals)
                                    if not get_pc_value() in pc_vals:
                                        #logger.debug("ADDING!!!!!\n")
                                        arr_values.append(test_array_val)
                                        pc_vals.append(get_pc_value()) 
                            #logger.debug(pc_vals)
                            #logger.debug(arg_values)
                            new_arr_val_len = len(arr_values)
                            if new_arr_val_len == arr_val_length:
                                fixed = True
                        arr_values.append("([C:])")
                        #logger.debug(arr_values)
                        array_input = True
                        #raise NotImplementedError(f"Don't know how to handle argument type {a}")
                    case "[I":
                        if array_input:
                            continue
                        array_val = "([I:"
                        pc_vals = [get_pc_value()]
                        #logger.debug(pc_vals)
                        #logger.debug(char_test_vals)
                        for integer in int_test_vals:
                            set_pc_value(0)
                            #logger.debug(f"The pc at the start is: {get_pc_value()}")
                            test_array_val = array_val + integer + "])"
                            input = jpamb.parse_input(test_array_val)
                            #logger.debug(input)
                            logger.disable("interpreter")
                            execute(methodid, input)
                            logger.enable("interpreter")
                            #logger.debug(f"The current pc value is: {get_pc_value()}")
                            if not get_pc_value() in pc_vals:
                                arr_values.append(test_array_val)
                                pc_vals.append(get_pc_value()) 
                        #logger.debug(pc_vals)
                        #logger.debug(arg_values)
                        fixed = False
                        while not fixed:
                            arr_val_length = len(arr_values)
                            for arr_val in arr_values:
                                #logger.debug(arg_val)
                                array_val = arr_val[0:-2] + ","
                                for integer in int_test_vals:
                                    set_pc_value(0)
                                    #logger.debug(f"The pc at the start is: {get_pc_value()}")
                                    test_array_val = array_val + integer + "])"
                                    input = jpamb.parse_input(test_array_val)
                                    #logger.debug(input)
                                    logger.disable("interpreter")
                                    execute(methodid, input)
                                    logger.enable("interpreter")
                                    #logger.debug(f"The current pc value is: {get_pc_value()}")
                                    #logger.debug(not get_pc_value() in pc_vals)
                                    if not get_pc_value() in pc_vals:
                                        #logger.debug("ADDING!!!!!\n")
                                        arr_values.append(test_array_val)
                                        pc_vals.append(get_pc_value()) 
                            #logger.debug(pc_vals)
                            #logger.debug(arg_values)
                            new_arr_val_len = len(arr_values)
                            if new_arr_val_len == arr_val_length:
                                fixed = True
                        arr_values.append("([I:])")
                        #logger.debug(arr_values)
                        array_input = True
                        #raise NotImplementedError(f"Don't know how to handle argument type {a}")
                fixed_arg_index //= len(int_test_vals) if a == "I" else len(bool_test_vals) if a == "Z" else len(string_test_vals) if a == "Ljava/lang/String;" else len(char_test_vals) if a == "C" else 1
            if array_input:
                for arr_val in arr_values:
                    arg_values = [arr_val]
                    input = jpamb.parse_input(f"({",".join(arg_values)})")
                    logger.disable("interpreter")
                    state = execute(methodid, input)
                    logger.enable("interpreter")
                    states.add(state)
            #logger.debug(f"{methodid}, {input}")
            else:
                #logger.debug(arg_values)
                input = jpamb.parse_input(f"({",".join(arg_values)})")
                #logger.debug(input)
                logger.disable("interpreter")
                state = execute(methodid, input)
                logger.enable("interpreter")
                #logger.debug(state)
                states.add(state)
            #logger.debug(f"{state}")


        for _ in range(fuzzing_tests):
            arg_values = []
            for a in arg_types:
                match a:
                    case "I":
                        arg_values.append(str(random.randint(java_min_int, java_max_int)))
                    case "Z":
                        arg_values.append(random.choice(["true", "false"]))
                    case _:
                        raise NotImplementedError(f"Don't know how to handle argument type {a}")
                    
            input = jpamb.parse_input(f"({",".join(arg_values)})")
            logger.disable("interpreter")
            state = execute(methodid, input)
            logger.enable("interpreter")
            states.add(state)      

    if "assertion error" in states:
        assertion_error_chance = "100%"
    else:
        assertion_error_chance = "0%"

    if "ok" in states:
        ok_chance = "100%" 
    else:
        ok_chance = "5%"

    if "divide by zero" in states:
        divide_by_zero_chance = "100%" 
    else:
        divide_by_zero_chance = "0%"
        
    if "out of bounds" in states:
        out_of_bounds_chance = "100%"
    else:
        out_of_bounds_chance = "0%"

    if "null pointer" in states: 
        null_pointer_chance = "100%"
    else:
        null_pointer_chance = "0%"

    if "*" in states: #how to deal with recursive functions?
        infinite_loop_chance = "90%"
    else:
        infinite_loop_chance = "0%"
    
    if "vulnerable" in states:
        vulnerable = "100%"
    else:
        vulnerable = "5%"

        # if array_input:
        #     ok_chance = "50%"
        #     divide_by_zero_chance = "50%"
        #     assertion_error_chance = "50%"
        #     out_of_bounds_chance = "50%"
        #     null_pointer_chance = "50%"
        #     infinite_loop_chance = "50%"
            

    # Output predictions for all 6 possible outcomes
    print(f"ok;{ok_chance}")
    print(f"divide by zero;{divide_by_zero_chance}")
    print(f"assertion error;{assertion_error_chance}")
    print(f"out of bounds;{out_of_bounds_chance}")
    print(f"null pointer;{null_pointer_chance}")
    print(f"*;{infinite_loop_chance}")
    print(f"vulnerable;{vulnerable}")

def static_analysis(methodid):

    found_vulnerability = False

    #Taint Analysis
    try:
        found_vulnerability = is_method_tainted(methodid)
    except Exception as e:
        logger.warning(f"Taint Analysis failed: {e}")
    
    if not found_vulnerability:
        #Abstract taint analysis
        try:
            input_str = generate_dummy_input(methodid)
            input = jpamb.parse_input(input_str)

            found_vulnerability = abstract_taint_res(methodid, input)
        except Exception as e:
            logger.warning(f"Taint Abstraction analysis failed: {e}")

    return found_vulnerability

def generate_dummy_input(methodid):
    params = methodid.extension.params._elements
    
    if not params:
        return "()"
    
    dummy_values = []
    for param in params:
        param_str = str(param)
        if "String" in param_str:
            dummy_values.append('"dummy"')
        elif param_str == "I":  # int
            dummy_values.append("0")
        elif param_str == "Z":  # boolean
            dummy_values.append("true")
        elif param_str == "C":  # char
            dummy_values.append("'a'")
        elif param_str.startswith("["):  # array
            elem_type = param_str[1:] 
            dummy_values.append(f"([{elem_type}:])") 
        else:
            dummy_values.append('"dummy"')
    
    return f"({', '.join(dummy_values)})"


# this example shows minimal working program without any imports.
#  this is especially useful for people building it in other programming languages
if len(sys.argv) == 2 and sys.argv[1] == "info":
    # Output the 5 required info lines
    print("Dynamic Analysis")
    print("1.2")
    print("Kageklubben")
    print("simple,tricky,loops,calls,arrays,python,dynamic")
    print("no")  # Use any other string to share system info
else:
    # Get the method we need to analyze
    classname, methodname, args = re.match(r"(.*)\.(.*):(.*)", sys.argv[1]).groups()

    methodid = jpamb.parse_methodid(sys.argv[1])

    is_vulnerable = static_analysis(methodid)

    if is_vulnerable:
        dynamic_analysis(methodid)
    # else:
    #     # guess 50% for all outcomes
    #     print("ok;50%")
    #     print("divide by zero;50%")
    #     print("assertion error;50%")
    #     print("out of bounds;50%")
    #     print("null pointer;50%")
    #     print("*;50%")
    #     print("vulnerable;50%")