#!/usr/bin/env python3
import sys
import re
from interpreter import *
import jpamb
import random
from loguru import logger
import tree_sitter
import tree_sitter_java

def to_ast(node):
    if node.type in {"{", "}", ";", "(", ")", "[", "]"}:
        return None

    children = [to_ast(c) for c in node.children]
    children = [c for c in children if c is not None]
    return {
        "type": node.type,
        "text": node.text.decode(),
        "children": children
    }

def find_ident_in_children(ast): #add case for method_invocation to model sanitization
    idents = set()
    should_skip = False
    for node in ast:
        if should_skip:
            should_skip = False
            continue
        match node['type']:
            case 'identifier':
                idents.add(node['text'])
            case '.': #skipping method identifier from objects ex. equals in s.equals("...")
                should_skip = True
            case _ if len(node['children']) > 0:
                sub_idents = find_ident_in_children(node['children'])
                idents = set.union(idents, sub_idents)
            case _:
                continue
    return idents

def flows(ast, seen_methods, implicit_variables=set()):
    res = set()
    for node in ast:
        #logger.debug(node['type'])
        #logger.debug(node['text'])
        match node['type']:
            case 'assert_statement' | 'assert': # If we have an assert statement, we check if any unsafe variables are used. 
                idents = find_ident_in_children(node['children'])
                total_idents = set.union(idents, implicit_variables)
                #for var in unsafe_variables:
                for var in total_idents:
                    res.add((var, 'assert'))
            case 'return_statement' | 'return':
                idents = find_ident_in_children(node['children'])
                total_idents = set.union(idents, implicit_variables)
                #for var in unsafe_variables:
                for var in total_idents:
                    res.add((var, 'return'))
            case 'if_statement': #how to handle else statements?
                if_childs = node['children']
                if len(if_childs) > 2: # not an empty if
                    guard_expression = if_childs[1] #skipping the first child which is just an "if" node
                    new_implicit_vars = set.union(find_ident_in_children(guard_expression['children']), implicit_variables) #fix else if
                    res = set.union(res, flows(if_childs[2]['children'], seen_methods, new_implicit_vars)) # not only if_childs[2]
                    if len(if_childs) >= 5: # with else (how about more if elses? maybe goes back to here)
                        res = set.union(res, flows(if_childs[4]['children'], seen_methods, new_implicit_vars))
                    # children will always exists
            case 'while_statement':
                while_childs = node['children']
                if len(while_childs) > 2: # not an empty while loop
                    guard_expression = while_childs[1] # skipping the "while" node
                    new_implicit_vars = set.union(find_ident_in_children(guard_expression['children']), implicit_variables)
                    res = set.union(res, flows(while_childs[2]['children'], seen_methods, new_implicit_vars))
                #logger.debug(node['text'])
            case 'for_statement':
                for_childs = node['children']
                if len(for_childs) > 4: # Thank you for being a normal human being (for loop with initialization, termination, increment and body)
                    # for_childs[0] is just a node with text "for"
                    init_flows = flows(for_childs[1]['children'], implicit_variables) # checking for flows in the initialization expression
                    body_implicit_variables = set.union(find_ident_in_children(for_childs[2]['children']), implicit_variables) # checking for new implicit flow variables in termination expression
                    update_expr_flows = flows(for_childs[3]['children'], seen_methods, body_implicit_variables)
                    body_flows = flows(for_childs[4]['children'], seen_methods, body_implicit_variables) #two (or more) level flow from other expressions not added
                    res = set.union(res, init_flows, update_expr_flows, body_flows)
                elif len(for_childs) <= 4: # Who the fuck does this?
                    exit(f"For loop with {len(for_childs)} arguments")
            case 'expression_statement': #add update expression
                #logger.debug(node)
                res = set.union(res, flows(node['children'], seen_methods, implicit_variables))
            case 'method_invocation':
                method_name = node['children'][0]['text']
                if not method_name in seen_methods:
                    seen_methods.append(method_name)
                    res = set.union(res, method_flow(method_name, seen_methods))
                #method_args = node['children'][1]['text']
            case 'update_expression': # i++
                updated_ident = node['children'][0]["text"]
                total_idents = set.union(implicit_variables, updated_ident)
                #for var in unsafe_variables:
                for var in total_idents:
                    res.add((var, updated_ident))
            #case 'block':
                #logger.debug(node)
            case 'assignment_expression':
                #logger.debug(node)
                ident_to = ""
                extra_idents = set()
                if (node['children'][0]['type'] == 'array_access'):
                    ident_to = node['children'][0]['children'][0]['text']
                    extra_idents.union(extra_idents, find_ident_in_children(node['children'][0]["children"][1:]))
                else:
                    ident_to = node['children'][0]['text'] # the identifier of the variable being assigned to
                idents_from = find_ident_in_children(node['children'][1:]) # the identifier of variables using in expression
                total_idents = set.union(idents_from, implicit_variables)
                total_idents = set.union(total_idents, extra_idents)
                for var in total_idents:
                    res.add((var, ident_to))
            case 'enhanced_for_statement':
                for_each_childs = node['children']
                #first child is for
                #second childs is integral_type 
                #third child is identifier
                #4th child is :
                #5th child is method_invocation
                new_implicit_vars = set.union(implicit_variables, find_ident_in_children(for_each_childs[4]['children']))
                #method_name = for_each_childs[4]['children'][0]['text']
                method_flows = flows([for_each_childs[4]], seen_methods)
                #logger.debug(method_flows)
                # if 
                # new_seen_methods = seen_methods.append(method_name)
                # method_flows = method_flow(method_name, )
                #6th child is the body
                body_flows = flows(for_each_childs[5]['children'], seen_methods, new_implicit_vars)
                res = set.union(res, body_flows)
                res = set.union(res, method_flows)
                #res = set.union(res, method_flows)
            case 'local_variable_declaration':
                #logger.debug(node) # consists of type and variable declaration
                res = set.union(res, flows(node['children'][1:], implicit_variables)) #variable declarator child. 1st child is type
                #{'type': 'local_variable_declaration', 'text': 'String u = t + s;', 'children':
                #  [
                #   {'type': 'type_identifier', 'text': 'String', 'children': []}, 
                #   {'type': 'variable_declarator', 'text': 'u = t + s', 'children': 
                #       [{'type': 'identifier', 'text': 'u', 'children': []}, 
                #       {'type': '=', 'text': '=', 'children': []}, 
                #       {'type': 'binary_expression', 'text': 't + s', 'children': 
                #           [{'type': 'identifier', 'text': 't', 'children': []}, 
                #           {'type': '+', 'text': '+', 'children': []}, 
                #           {'type': 'identifier', 'text': 's', 'children': []}]
                #       }]
                #   }]
                #}
            case 'variable_declarator':
                var_dec_childs = node['children']
                ident = var_dec_childs[0]['text']
                #2nd child is =                
                # expression used to declare
                rhs_idents = find_ident_in_children(var_dec_childs[2:])
                total_idents = set.union(rhs_idents, implicit_variables)
                for var in total_idents:
                    res.add((var, ident))
            case _:
                continue
            # local variable declaration
            # variable declarator
    return res


def method_flow(method_name, seen_methods): #only works for method in the same class
    class_q = tree_sitter.Query(JAVA_LANGUAGE,
        f"""
        (class_declaration 
            name: ((identifier) @class-name 
                (#eq? @class-name "{simple_classname}"))) @class
    """
    )

    #class_taint_dict[simple_classname] = {}

    for node in tree_sitter.QueryCursor(class_q).captures(tree.root_node)["class"]:
        break
    else:
        #could not find class with name {simple_classname}
        sys.exit(-1)

    method_q = tree_sitter.Query(JAVA_LANGUAGE,
        f"""
        (method_declaration 
        name: (identifier) @method-name
        parameters: (formal_parameters
            (formal_parameter
                type: (_) @param-type
                name: (identifier) @param-name
            )*
            ("," (formal_parameter
                type: (_) @param-type
                name: (identifier) @param-name
            ))*
        ) 
        (#eq? @method-name "{method_name}")
        ) @method
    """
    )

    #class_taint_dict[simple_classname][method_name] = {}

    cursor = tree_sitter.QueryCursor(method_q)
    captures = cursor.captures(tree.root_node)
    
    #logger.debug(captures.items())

    param_names = []
    param_types = []
    
    for name, nodes in captures.items():
        if name == "param-name":
            for node in nodes:
                param_names.append(node.text.decode())
        if name == "param-type":
            for node in nodes: 
                param_types.append(node.text.decode())
    #method_args = list(zip(param_names, param_types))
    #logger.debug(method_args)

    #class_taint_dict[simple_classname][method_name]['method_args'] = method_args
    #logger.debug(class_taint_dict)

    body = None
    for node in captures["method"]:
        body = node.child_by_field_name("body")
        method_body = body.text.decode()
        logger.debug(param_names)
        logger.debug(method_body)
    
    # if not body == None:
    #     for stmt in body.children:
    #         print(stmt.type, stmt.text.decode())

    ast_body = to_ast(body)
    logger.debug(ast_body['children'])
    # for node in ast_body['children']:
    #     logger.debug(node)
    # logger.debug(f'method called: {method_name}')
    # logger.debug("-------------------\n")
    # logger.debug(ast_body)
    #param_names.append("u")
    flow_dict = flows(ast_body['children'], seen_methods)
    #logger.debug(flow_dict)
    return flow_dict

# method to handle flow through method calls
# remember to map variable names from calls to argument names
# perhaps name variables as classname_methodname_identifier
# maybe just flow to method invocations/method names
# for recursive methods keep track of visited methods and stop if already seen (not sound) (maybe sound if also keep track of args)

# this example shows minimal working program without any imports.
#  this is especially useful for people building it in other programming languages
if len(sys.argv) == 2 and sys.argv[1] == "info":
    # Output the 5 required info lines
    print("Taint analysis")
    print("1.0")
    print("Kageklubben")
    print("SQL,taint")
    print("no")  # Use any other string to share system info
else:
    # Get the method we need to analyze
    classname, methodname, args = re.match(r"(.*)\.(.*):(.*)", sys.argv[1]).groups()
    java_max_int = 2**32-1
    java_min_int = -2**32

    #class_taint_dict = {}

    methodid = jpamb.parse_methodid(sys.argv[1])

    JAVA_LANGUAGE = tree_sitter.Language(tree_sitter_java.language())
    parser = tree_sitter.Parser(JAVA_LANGUAGE)


    srcfile = jpamb.sourcefile(methodid)

    with open(srcfile, "rb") as f:
        tree = parser.parse(f.read())

    simple_classname = str(methodid.classname.name)
    method_name = methodid.extension.name


    flow_dict = method_flow(method_name, [method_name])
    logger.debug(flow_dict)

    ok_chance = "50%"
    divide_by_zero_chance = "50%"
    assertion_error_chance = "50%"
    out_of_bounds_chance = "50%"
    null_pointer_chance = "50%"
    infinite_loop_chance = "50%"
    vulnerable = "50%"

    if len(flow_dict) > 0:
        vulnerable = "100%"
    else:
        vulnerable = "0%"
    

    # Output predictions for all 6 possible outcomes
    print(f"ok;{ok_chance}")
    print(f"divide by zero;{divide_by_zero_chance}")
    print(f"assertion error;{assertion_error_chance}")
    print(f"out of bounds;{out_of_bounds_chance}")
    print(f"null pointer;{null_pointer_chance}")
    print(f"*;{infinite_loop_chance}")
    print(f"vulnerable;{vulnerable}")



    
    
