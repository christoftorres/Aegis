#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import copy
import time
import settings

from textx import metamodel_from_file
from utils import *

def load_model(filename):
    try:
        if settings.DEBUG_MODE:
            print("Loading patterns...")
            parsing_begin = time.time()
        metamodel = metamodel_from_file(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'grammar.tx'), memoization=True)
        model = metamodel.model_from_file(filename)
        if settings.DEBUG_MODE:
            parsing_end = time.time()
            parsing_delta = parsing_end - parsing_begin
            print("Done. Loading patterns took %.2f second(s)." % parsing_delta)
        return model
    except Exception as e:
        print(e.message)
    return None

def evaluate_pattern(pattern, trace, step, taint_runner, call_tree, control_flow_graph, dependencies):
    pattern_name = pattern.__class__.__name__

    if isinstance(pattern, int):
        return pattern

    if isinstance(pattern, str):
        if "transaction" in pattern:
            return trace[step]["transaction"][pattern.split('.')[1]]
        elif pattern in ["pc", "depth"]:
            return trace[step][pattern]
        elif pattern == "opcode":
            return trace[step]["op"]
        elif pattern == "address":
            return control_flow_graph.get_contract_address(step)
        else:
            return pattern

    if pattern_name == "GreaterThan":
        x, y = convert_hex_to_int(evaluate_pattern(pattern.x, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)), convert_hex_to_int(evaluate_pattern(pattern.y, trace, step, taint_runner, call_tree, control_flow_graph, dependencies))
        return x > y

    if pattern_name == "LessThan":
        x, y = convert_hex_to_int(evaluate_pattern(pattern.x, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)), convert_hex_to_int(evaluate_pattern(pattern.y, trace, step, taint_runner, call_tree, control_flow_graph, dependencies))
        return x < y

    if pattern_name == "GreaterOrEqual":
        x, y = convert_hex_to_int(evaluate_pattern(pattern.x, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)), convert_hex_to_int(evaluate_pattern(pattern.y, trace, step, taint_runner, call_tree, control_flow_graph, dependencies))
        return x >= y

    if pattern_name == "LessOrEqual":
        x, y = convert_hex_to_int(evaluate_pattern(pattern.x, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)), convert_hex_to_int(evaluate_pattern(pattern.y, trace, step, taint_runner, call_tree, control_flow_graph, dependencies))
        return x <= y

    if pattern_name == "Equal":
        x, y = convert_hex_to_int(evaluate_pattern(pattern.x, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)), convert_hex_to_int(evaluate_pattern(pattern.y, trace, step, taint_runner, call_tree, control_flow_graph, dependencies))
        return x == y

    if pattern_name == "NotEqual":
        x, y = convert_hex_to_int(evaluate_pattern(pattern.x, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)), convert_hex_to_int(evaluate_pattern(pattern.y, trace, step, taint_runner, call_tree, control_flow_graph, dependencies))
        return x != y

    if pattern_name == "BooleanAnd":
        return evaluate_pattern(pattern.x, trace, step, taint_runner, call_tree, control_flow_graph, dependencies) and evaluate_pattern(pattern.y, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)

    if pattern_name == "In":
        return evaluate_pattern(pattern.element, trace, step, taint_runner, call_tree, control_flow_graph, dependencies) in pattern.elements

    if pattern_name == "Stack":
        return hex(int(trace[step]["stack"][len(trace[step]["stack"])-1-pattern.index], 16))

    if pattern_name == "Memory":
        offset, size = 2 * convert_hex_to_int(evaluate_pattern(pattern.offset, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)), 2 * convert_hex_to_int(evaluate_pattern(pattern.size, trace, step, taint_runner, call_tree, control_flow_graph, dependencies))
        return ''.join(trace[step]["memory"])[offset:offset+size]

    if pattern_name == "Follows":
        dependency_detected = False
        if evaluate_pattern(pattern.source, trace, step, taint_runner, call_tree, control_flow_graph, dependencies):
            if not pattern in dependencies:
                dependencies[pattern] = {}
                dependencies[pattern]["sources"] = []
                dependencies[pattern]["destinations"] = []
                dependencies[pattern]["dependencies"] = []
            if not step in dependencies[pattern]["sources"]:
                dependencies[pattern]["sources"].append(step)
        if evaluate_pattern(pattern.destination, trace, step, taint_runner, call_tree, control_flow_graph, dependencies):
            if pattern in dependencies:
                dependencies[pattern]["destinations"].append(step)
                for source in reversed(dependencies[pattern]["sources"]):
                    if source != step:
                        dependency = {}
                        dependency["source"] = source
                        dependency["destination"] = step
                        if not dependency in dependencies[pattern]["dependencies"]:
                            if pattern.condition:
                                if evaluate_pattern(pattern.condition, trace, step, taint_runner, call_tree, control_flow_graph, {pattern: {"dependencies": [dependency]}}):
                                    dependencies[pattern]["dependencies"].append(dependency)
                                    dependency_detected = True
                                    break
                            else:
                                dependencies[pattern]["dependencies"].append(dependency)
                                dependency_detected = True
                                break
        return dependency_detected

    if pattern_name == "DataDependency":
        dependency_detected = False
        if evaluate_pattern(pattern.source, trace, step, taint_runner, call_tree, control_flow_graph, dependencies):
            taint_runner.introduce_taint(step, trace[step])
            if not pattern in dependencies:
                dependencies[pattern] = {}
                dependencies[pattern]["sources"] = []
                dependencies[pattern]["destinations"] = []
                dependencies[pattern]["dependencies"] = []
            if not step in dependencies[pattern]["sources"]:
                dependencies[pattern]["sources"].append(step)
        if evaluate_pattern(pattern.destination, trace, step, taint_runner, call_tree, control_flow_graph, dependencies):
            if pattern in dependencies:
                dependencies[pattern]["destinations"].append(step)
                for source in reversed(dependencies[pattern]["sources"]):
                    if source != step:
                        if taint_runner.check_taint(source, trace[step]):
                            dependency = {}
                            dependency["source"] = source
                            dependency["destination"] = step
                            if not dependency in dependencies[pattern]["dependencies"]:
                                if pattern.condition:
                                    if evaluate_pattern(pattern.condition, trace, step, taint_runner, call_tree, control_flow_graph, {pattern: {"dependencies": [dependency]}}):
                                        dependencies[pattern]["dependencies"].append(dependency)
                                        dependency_detected = True
                                        break
                                else:
                                    dependencies[pattern]["dependencies"].append(dependency)
                                    dependency_detected = True
                                    break
        return dependency_detected

    if pattern_name == "ControlDependency":
        dependency_detected = False
        if evaluate_pattern(pattern.source, trace, step, taint_runner, call_tree, control_flow_graph, dependencies):
            if not pattern in dependencies:
                dependencies[pattern] = {}
                dependencies[pattern]["sources"] = []
                dependencies[pattern]["destinations"] = []
                dependencies[pattern]["dependencies"] = []
            if not step in dependencies[pattern]["sources"]:
                dependencies[pattern]["sources"].append(step)
        if evaluate_pattern(pattern.destination, trace, step, taint_runner, call_tree, control_flow_graph, dependencies):
            if pattern in dependencies:
                dependencies[pattern]["destinations"].append(step)
                for source in reversed(dependencies[pattern]["sources"]):
                    if source != step:
                        if call_tree.check_call_dependency(source, step):
                            dependency = {}
                            dependency["source"] = source
                            dependency["destination"] = step
                            if not dependency in dependencies[pattern]["dependencies"]:
                                if pattern.condition:
                                    if evaluate_pattern(pattern.condition, trace, step, taint_runner, call_tree, control_flow_graph, {pattern: {"dependencies": [dependency]}}):
                                        dependencies[pattern]["dependencies"].append(dependency)
                                        dependency_detected = True
                                        break
                                else:
                                    dependencies[pattern]["dependencies"].append(dependency)
                                    dependency_detected = True
                                    break
        return dependency_detected

    if pattern_name == "Source":
        property = pattern.property
        while pattern.parent and not pattern.__class__.__name__ in ["Follows", "DataDependency", "ControlDependency"]:
            pattern = pattern.parent
        return evaluate_pattern(property, trace, dependencies[pattern]["dependencies"][0]["source"], taint_runner, call_tree, control_flow_graph, dependencies)

    if pattern_name == "Destination":
        return evaluate_pattern(pattern.property, trace, step, taint_runner, call_tree, control_flow_graph, dependencies)

    print("Unknown operation: "+str(pattern_name))

def pattern_to_str(pattern, trace, step, control_flow_graph, dependencies):
    pattern_name = pattern.__class__.__name__

    if isinstance(pattern, int):
        return str(pattern)

    if isinstance(pattern, str):
        if "transaction" in pattern:
            return trace[step]["transaction"][pattern.split('.')[1]]
        elif pattern in ["pc", "depth"]:
            return str(trace[step][pattern])
        elif pattern == "opcode":
            return "opcode"
        elif pattern == "address":
            return control_flow_graph.get_contract_address(step)
        else:
            return pattern

    if pattern_name == "GreaterThan":
        x, y = pattern_to_str(pattern.x, trace, step, control_flow_graph, dependencies), pattern_to_str(pattern.y, trace, step, control_flow_graph, dependencies)
        return '('+str(x)+' > '+str(y)+')'

    if pattern_name == "LessThan":
        x, y = pattern_to_str(pattern.x, trace, step, control_flow_graph, dependencies), pattern_to_str(pattern.y, trace, step, control_flow_graph, dependencies)
        return '('+str(x)+' < '+str(y)+')'

    if pattern_name == "GreaterOrEqual":
        x, y = pattern_to_str(pattern.x, trace, step, control_flow_graph, dependencies), pattern_to_str(pattern.y, trace, step, control_flow_graph, dependencies)
        return '('+str(x)+' >= '+str(y)+')'

    if pattern_name == "LessOrEqual":
        x, y = pattern_to_str(pattern.x, trace, step, control_flow_graph, dependencies), pattern_to_str(pattern.y, trace, step, control_flow_graph, dependencies)
        return '('+str(x)+' <= '+str(y)+')'

    if pattern_name == "Equal":
        x, y = pattern_to_str(pattern.x, trace, step, control_flow_graph, dependencies), pattern_to_str(pattern.y, trace, step, control_flow_graph, dependencies)
        return '('+str(x)+' == '+str(y)+')'

    if pattern_name == "NotEqual":
        x, y = pattern_to_str(pattern.x, trace, step, control_flow_graph, dependencies), pattern_to_str(pattern.y, trace, step, control_flow_graph, dependencies)
        return '('+str(x)+' != '+str(y)+')'

    if pattern_name == "BooleanAnd":
        x, y = pattern_to_str(pattern.x, trace, step, control_flow_graph, dependencies), pattern_to_str(pattern.y, trace, step, control_flow_graph, dependencies)
        return '('+str(x)+' && '+str(y)+')'

    if pattern_name == "In":
        return '('+str(pattern_to_str(pattern.element, trace, step, control_flow_graph, dependencies))+' in '+str(pattern.elements)+')'

    if pattern_name == "Stack":
        return hex(int(trace[step]["stack"][len(trace[step]["stack"])-1-pattern.index], 16))

    if pattern_name == "Memory":
        offset, size = 2 * convert_hex_to_int(pattern_to_str(pattern.offset, trace, step, control_flow_graph, dependencies)), 2 * convert_hex_to_int(pattern_to_str(pattern.size, trace, step, control_flow_graph, dependencies))
        return ''.join(trace[step]["memory"])[offset:offset+size]

    if pattern_name == "Follows":
        for dependency in dependencies[pattern]["dependencies"]:
            if dependency["destination"] == step:
                if not pattern.condition:
                    return '('+str(pattern_to_str(pattern.source, trace, dependency["source"], control_flow_graph, dependencies))+' --> '+str(pattern_to_str(pattern.destination, trace, dependency["destination"], control_flow_graph, dependencies))+')'
                else:
                    return '('+str(pattern_to_str(pattern.source, trace, dependency["source"], control_flow_graph, dependencies))+' --> '+str(pattern_to_str(pattern.destination, trace, dependency["destination"], control_flow_graph, dependencies))+' where '+str(pattern_to_str(pattern.condition, trace, step, control_flow_graph, {pattern: {"dependencies": [dependency]}}))+')'
        return '('+str(pattern_to_str(pattern.source, trace, dependencies[pattern]["sources"][0], control_flow_graph, dependencies))+' --> '+str(pattern_to_str(pattern.destination, trace, dependencies[pattern]["destinations"][0] if len(dependencies[pattern]["destinations"]) > 0 else None, control_flow_graph, dependencies))+')'

    if pattern_name == "DataDependency":
        for dependency in dependencies[pattern]["dependencies"]:
            if dependency["destination"] == step:
                if not pattern.condition:
                    return '('+str(pattern_to_str(pattern.source, trace, dependency["source"], control_flow_graph, dependencies))+' ~~> '+str(pattern_to_str(pattern.destination, trace, dependency["destination"], control_flow_graph, dependencies))+')'
                else:
                    return '('+str(pattern_to_str(pattern.source, trace, dependency["source"], control_flow_graph, dependencies))+' ~~> '+str(pattern_to_str(pattern.destination, trace, dependency["destination"], control_flow_graph, dependencies))+' where '+str(pattern_to_str(pattern.condition, trace, step, control_flow_graph, {pattern: {"dependencies": [dependency]}}))+')'
        return '('+str(pattern_to_str(pattern.source, trace, dependencies[pattern]["sources"][0], control_flow_graph, dependencies))+' ~~> '+str(pattern_to_str(pattern.destination, trace, dependencies[pattern]["destinations"][0] if len(dependencies[pattern]["destinations"]) > 0 else None, control_flow_graph, dependencies))+')'

    if pattern_name == "ControlDependency":
        for dependency in dependencies[pattern]["dependencies"]:
            if dependency["destination"] == step:
                if not pattern.condition:
                    return '('+str(pattern_to_str(pattern.source, trace, dependency["source"], control_flow_graph, dependencies))+' ==> '+str(pattern_to_str(pattern.destination, trace, dependency["destination"], control_flow_graph, dependencies))+')'
                else:
                    return '('+str(pattern_to_str(pattern.source, trace, dependency["source"], control_flow_graph, dependencies))+' ==> '+str(pattern_to_str(pattern.destination, trace, dependency["destination"], control_flow_graph, dependencies))+' where '+str(pattern_to_str(pattern.condition, trace, step, control_flow_graph, {pattern: {"dependencies": [dependency]}}))+')'
        return '('+str(pattern_to_str(pattern.source, trace, dependencies[pattern]["sources"][0], control_flow_graph, dependencies))+' ==> '+str(pattern_to_str(pattern.destination, trace, dependencies[pattern]["destinations"][0] if len(dependencies[pattern]["destinations"]) > 0 else None, control_flow_graph, dependencies))+')'

    if pattern_name == "Source":
        property = pattern.property
        while pattern.parent and not pattern.__class__.__name__ in ["Follows", "DataDependency", "ControlDependency"]:
            pattern = pattern.parent
        return pattern_to_str(property, trace, dependencies[pattern]["dependencies"][0]["source"], control_flow_graph, dependencies)

    if pattern_name == "Destination":
        return pattern_to_str(pattern.property, trace, step, control_flow_graph, dependencies)

    print("Unknown pattern: "+str(pattern_name))
