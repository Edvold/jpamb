# #!/usr/bin/env python3
# import sys
# import re
# from interpreter import *
# import jpamb
# import random
# from loguru import logger
# import tree_sitter
# import tree_sitter_java

# # this example shows minimal working program without any imports.
# #  this is especially useful for people building it in other programming languages
# if len(sys.argv) == 2 and sys.argv[1] == "info":
#     # Output the 5 required info lines
#     print("Dynamic Analysis")
#     print("1.2")
#     print("Kageklubben")
#     print("simple,tricky,loops,calls,arrays,python,dynamic")
#     print("no")  # Use any other string to share system info
# else:
#     # Get the method we need to analyze
#     classname, methodname, args = re.match(r"(.*)\.(.*):(.*)", sys.argv[1]).groups()
#     java_max_int = 2**32-1
#     java_min_int = -2**32

#     methodid = jpamb.parse_methodid(sys.argv[1])

#     int_test_vals = {"-1", "0", "1"}


#     JAVA_LANGUAGE = tree_sitter.Language(tree_sitter_java.language())
#     parser = tree_sitter.Parser(JAVA_LANGUAGE)


#     srcfile = jpamb.sourcefile(methodid)

#     with open(srcfile, "rb") as f:
#         tree = parser.parse(f.read())

#     simple_classname = str(methodid.classname.name)
    
#     class_q = tree_sitter.Query(JAVA_LANGUAGE,
#         f"""
#         (class_declaration 
#             name: ((identifier) @class-name 
#                 (#eq? @class-name "{simple_classname}"))) @class
#     """
#     )

#     for node in tree_sitter.QueryCursor(class_q).captures(tree.root_node)["class"]:
#         break
#     else:
#         #could not find class with name {simple_classname}
#         sys.exit(-1)

#     method_name = methodid.extension.name

#     method_q = tree_sitter.Query(JAVA_LANGUAGE,
#         f"""
#         (method_declaration name: 
#         ((identifier) @method-name (#eq? @method-name "{method_name}"))
#         ) @method
#     """
#     )

#     for node in tree_sitter.QueryCursor(method_q).captures(node)["method"]:
#         body = node.child_by_field_name("body")
#         method_body = body.text.decode()
#         numbers_in_body = re.findall(r"\d+", method_body)
#         for n in numbers_in_body:
#             int_test_vals.add(n)
            

#     # Make predictions (improve these by looking at the Java code!)
#     ok_chance = "50%"
#     divide_by_zero_chance = "50%"
#     assertion_error_chance = "50%"
#     out_of_bounds_chance = "50%"
#     null_pointer_chance = "50%"
#     infinite_loop_chance = "50%"
#     completed_interpreter_classes = ["jpamb.cases.Simple", "jpamb.cases.Tricky", "jpamb.cases.Loops", "jpamb.cases.Calls", "jpamb.cases.Arrays"]

#     if classname in completed_interpreter_classes:

#         states = set()
#         int_test_vals = list(int_test_vals)
#         bool_test_vals = ["true", "false"]
#         array_input = False

#         fuzzing_tests = 0

#         if args.startswith("()"):
#             input = jpamb.parse_input("()")
#             logger.disable("interpreter")
#             state = execute(methodid, input)
#             logger.enable("interpreter")
#             states.add(state)
#         else:
#             arg_types = list(args)[1:-2]
#             for index in range(len(int_test_vals)*len(bool_test_vals)):
#                 arg_values = []
#                 for a in arg_types:
#                     match a:
#                         case "I":
#                             arg_values.append(str(int_test_vals[index % len(int_test_vals)]))
#                         case "Z":
#                             arg_values.append(str(bool_test_vals[index % len(bool_test_vals)]))
#                         case _:
#                             array_input = True
#                             break
#                             raise NotImplementedError(f"Don't know how to handle argument type {a}")
#                 if array_input:
#                     break        
#                 #logger.debug(f"{methodid}, {input}")
#                 input = jpamb.parse_input(f"({",".join(arg_values)})")
#                 logger.disable("interpreter")
#                 state = execute(methodid, input)
#                 logger.enable("interpreter")
#                 states.add(state)
#                 #logger.debug(f"{state}")


#             for _ in range(fuzzing_tests):
#                 arg_values = []
#                 for a in arg_types:
#                     match a:
#                         case "I":
#                             arg_values.append(str(random.randint(java_min_int, java_max_int)))
#                         case "Z":
#                             arg_values.append(random.choice(["true", "false"]))
#                         case _:
#                             raise NotImplementedError(f"Don't know how to handle argument type {a}")
                        
#                 input = jpamb.parse_input(f"({",".join(arg_values)})")
#                 logger.disable("interpreter")
#                 state = execute(methodid, input)
#                 logger.enable("interpreter")
#                 states.add(state)      

#         if "assertion error" in states:
#             assertion_error_chance = "100%"
#         else:
#             assertion_error_chance = "0%"

#         if "ok" in states:
#             ok_chance = "100%" 
#         else:
#             ok_chance = "5%"

#         if "divide by zero" in states:
#             divide_by_zero_chance = "100%" 
#         else:
#             divide_by_zero_chance = "0%"
            
#         if "out of bounds" in states:
#             out_of_bounds_chance = "100%"
#         else:
#             out_of_bounds_chance = "0%"

#         if "null pointer" in states: 
#             null_pointer_chance = "100%"
#         else:
#             null_pointer_chance = "0%"

#         if "*" in states: #how to deal with recursive functions?
#             infinite_loop_chance = "90%"
#         else:
#             infinite_loop_chance = "0%"

#         if array_input:
#             ok_chance = "50%"
#             divide_by_zero_chance = "50%"
#             assertion_error_chance = "50%"
#             out_of_bounds_chance = "50%"
#             null_pointer_chance = "50%"
#             infinite_loop_chance = "50%"
            

#     # Output predictions for all 6 possible outcomes
#     print(f"ok;{ok_chance}")
#     print(f"divide by zero;{divide_by_zero_chance}")
#     print(f"assertion error;{assertion_error_chance}")
#     print(f"out of bounds;{out_of_bounds_chance}")
#     print(f"null pointer;{null_pointer_chance}")
#     print(f"*;{infinite_loop_chance}")
#!/usr/bin/env python3
import sys
import re
from interpreter import *
#from interpreter import current_pc_value
import jpamb
import random
from loguru import logger
import tree_sitter
import tree_sitter_java

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
    java_max_int = 2**32-1
    java_min_int = -2**32

    methodid = jpamb.parse_methodid(sys.argv[1])

    int_test_vals = {"-1", "0", "1"}
    char_test_vals = {"' '"}
    string_test_vals = {"\"\"", "\"\""}


    JAVA_LANGUAGE = tree_sitter.Language(tree_sitter_java.language())
    parser = tree_sitter.Parser(JAVA_LANGUAGE)


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
        string_in_body = re.findall(r"(\".*\")", method_body)
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
    completed_interpreter_classes = ["jpamb.cases.Simple", "jpamb.cases.Tricky", "jpamb.cases.Loops", "jpamb.cases.Calls", "jpamb.cases.Arrays", "jpamb.cases.Strings"]

    if classname in completed_interpreter_classes:

        states = set()
        int_test_vals = list(int_test_vals)
        bool_test_vals = ["true", "false"]
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
            #check if the type variables exist then var = len(set) else = 1
            for index in range(len(int_test_vals)*len(bool_test_vals)*len(char_test_vals)*len(string_test_vals)):
                arg_values = []
                arr_values = []
                # if "[I" in fixed_arg_types:
                #     print(f"ok;{ok_chance}")
                #     print(f"divide by zero;{divide_by_zero_chance}")
                #     print(f"assertion error;{assertion_error_chance}")
                #     print(f"out of bounds;{out_of_bounds_chance}")
                #     print(f"null pointer;{null_pointer_chance}")
                #     print(f"*;{infinite_loop_chance}")
                #     exit()
                for a in fixed_arg_types:
                    match a:
                        case "I":
                            arg_values.append(str(int_test_vals[index % len(int_test_vals)]))
                        case "Z":
                            arg_values.append(str(bool_test_vals[index % len(bool_test_vals)]))
                        case "Ljava/lang/String;":
                            arg_values.append(str(string_test_vals[index % len(string_test_vals)]))
                        case "C":
                            #NOBODY USES THIS SHIT PLEASE
                            arg_values.append(str(char_test_vals[index % len(char_test_vals)]))
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
