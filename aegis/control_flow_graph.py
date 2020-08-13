#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import copy
import subprocess
import settings

from web3 import Web3
from utils import normalize_32_byte_hex_address

class BasicBlock:
    def __init__(self):
        self.start_address    = 0
        self.end_address      = 0
        self.depth            = 0
        self.contract_address = 0
        self.instructions     = {}
    def __str__(self):
        string  = "---------Basic Block---------\n"
        string += "Start address: %d (0x%x)\n" % (self.start_address, self.start_address)
        string += "End address: %d (0x%x)\n" % (self.end_address, self.end_address)
        string += "Depth: %d \n" % (self.depth)
        string += "Contract address: 0x%x \n" % (self.contract_address)
        string += "Instructions: "+str(self.instructions)+"\n"
        string += "-----------------------------"
        return string
    def __hash__(self):
        return hash(str(self))
    def __eq__(self, _other):
        return self.__dict__ == _other.__dict__

    def set_start_address(self, start_address):
        self.start_address = start_address

    def get_start_address(self):
        return self.start_address

    def set_end_address(self, end_address):
        self.end_address = end_address

    def get_end_address(self):
        return self.end_address

    def set_depth(self, depth):
        self.depth = depth

    def get_depth(self):
        return self.depth

    def set_contract_address(self, contract_address):
        self.contract_address = contract_address

    def get_contract_address(self):
        return self.contract_address

    def add_instruction(self, key, value):
        self.instructions[key] = value

    def get_instructions(self):
        return self.instructions

class ControlFlowGraph:
    def __init__(self):
        self.edges = {}
        self.graphs = {}
        self.vertices = {}
        self.callstack = []
        self.bytecodes = {}
        self.contract_inputs = {}
        self.contract_dependencies = {}
        self.current_basic_block = None
        self.current_contract_address = None

    @staticmethod
    def graph_traversal(source, sink, visited):
        visited.append(sink)
        if source in visited:
            return True
        if len(sink.all_incoming_basic_blocks) > 0:
            return_values = []
            for basic_block in sink.all_incoming_basic_blocks:
                if not basic_block in visited and not ControlFlowGraph.graph_traversal(source, basic_block, visited[:]):
                    return False
        else:
            if not source in visited:
                return False
        return True

    def get_contract_input(self, step):
        return self.contract_inputs[step]

    def get_contract_address(self, step):
        return self.contract_dependencies[step]

    def execute(self, trace, step, transaction):
        if not self.current_contract_address:
            self.current_contract_address = transaction["to"]

        self.contract_dependencies[step] = self.current_contract_address

        if trace[step]["op"] in ["CALL", "CALLCODE"]:
            offset = 2 * int(trace[step]["stack"][-4], 16)
            size = 2 * int(trace[step]["stack"][-5], 16)
            self.contract_inputs[step] = ''.join(trace[step]["memory"])[offset:offset+size]
        elif trace[step]["op"] in ["DELEGATECALL", "STATICCALL"]:
            offset = 2 * int(trace[step]["stack"][-3], 16)
            size = 2 * int(trace[step]["stack"][-4], 16)
            self.contract_inputs[step] = ''.join(trace[step]["memory"])[offset:offset+size]
        elif not step-1 in self.contract_inputs:
            self.contract_inputs[step] = transaction["input"]
        else:
            self.contract_inputs[step] = self.contract_inputs[step-1]

        if settings.SAVE_CFG:
            if not self.current_basic_block:
                self.current_basic_block = BasicBlock()
                self.current_basic_block.set_start_address(trace[step]["pc"])
                self.current_basic_block.set_depth(trace[step]["depth"])
            instruction = trace[step]["op"]
            # Check for push instructions
            if "PUSH" in instruction and step+1 < len(trace):
                instruction += " "+hex(int(trace[step+1]["stack"][-1], 16))
            self.current_basic_block.add_instruction(trace[step]["pc"], instruction)
        # Check for basic block ending instructions
        if trace[step]["op"] in ["STOP", "RETURN", "SELFDESTRUCT", "SUICIDE", "REVERT", "ASSERTFAIL", "JUMP", "JUMPI", "CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"] or "error" in trace[step]:
            if settings.DEBUG_MODE and step+1 in trace and trace[step]["depth"] < trace[step+1]["depth"]:
                print("...........................................................................")
            if settings.SAVE_CFG:
                self.current_basic_block.set_end_address(trace[step]["pc"])
                self.current_basic_block.set_contract_address(self.current_contract_address)

            if step+1 in trace:
                # Check for contract calls
                if trace[step]["op"] in ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"]:
                    if settings.DEBUG_MODE:
                        print(" From: \t "+self.current_contract_address)
                    if trace[step]["depth"] < trace[step+1]["depth"]:
                        self.callstack.append(self.current_contract_address)
                        if trace[step]["op"] in ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"]:
                            self.current_contract_address = normalize_32_byte_hex_address(trace[step]["stack"][-2])
                        else:
                            i = step + 1
                            while trace[i]["depth"] > trace[step]["depth"]:
                                i += 1
                            self.current_contract_address = normalize_32_byte_hex_address(trace[i]["stack"][-1])
                    if settings.DEBUG_MODE:
                        print(" To: \t "+self.current_contract_address)
                        if trace[step]["op"] in ["CALL", "CALLCODE"]:
                            print(" Value:  "+str(Web3.fromWei(int(trace[step]["stack"][-3], 16), "ether"))+" ether")
                        print(" Input:  0x"+self.contract_inputs[step])
                        if trace[step+1]["stack"]:
                            print(" Return Value: "+str(trace[step+1]["stack"][-1]))

                # Check for terminating instructions or an error
                if trace[step]["depth"] > trace[step+1]["depth"]:
                    if len(self.callstack) > 0:
                        self.current_contract_address = self.callstack.pop()
                    else:
                        self.current_contract_address = transaction["to"]
            if settings.SAVE_CFG:
                # Add basic block to vertices
                if not self.current_basic_block.get_start_address() in self.vertices:
                    self.vertices[self.current_basic_block.get_start_address()] = {}
                self.vertices[self.current_basic_block.get_start_address()][self.current_basic_block.get_contract_address()] = copy.deepcopy(self.current_basic_block)
                # Add basic block to edges
                if not self.current_basic_block.get_start_address() in self.edges:
                    self.edges[self.current_basic_block.get_start_address()] = {}
                if not self.current_basic_block.get_contract_address() in self.edges[self.current_basic_block.get_start_address()]:
                    self.edges[self.current_basic_block.get_start_address()][self.current_basic_block.get_contract_address()] = []
                if step < len(trace)-1:
                    # Check for branches
                    if trace[step]["op"] == "JUMPI":
                        flag = int(trace[step]["stack"][-2], 16)
                        if flag != 0:
                            right_edge = {}
                            right_edge["contract"] = self.current_contract_address
                            right_edge["pc"] = int(trace[step]["stack"][-1], 16)
                            right_edge["label"] = "True"
                            if not right_edge in self.edges[self.current_basic_block.get_start_address()][self.current_basic_block.get_contract_address()]:
                                self.edges[self.current_basic_block.get_start_address()][self.current_basic_block.get_contract_address()].append(right_edge)
                        else:
                            left_edge = {}
                            left_edge["contract"] = self.current_contract_address
                            left_edge["pc"] = trace[step+1]["pc"]
                            left_edge["label"] = "False"
                            if not left_edge in self.edges[self.current_basic_block.get_start_address()][self.current_basic_block.get_contract_address()]:
                                self.edges[self.current_basic_block.get_start_address()][self.current_basic_block.get_contract_address()].append(left_edge)
                    else:
                        edge = {}
                        edge["contract"] = self.current_contract_address
                        edge["pc"] = trace[step+1]["pc"]
                        if trace[step]["op"] in ["CALL", "CALLCODE"]:
                            if not "error" in trace[step]:
                                edge["label"] = trace[step]["op"]+" (to: "+hex(int(trace[step]["stack"][-2], 16))+", value: "+str(settings.W3.fromWei(int(trace[step]["stack"][-3], 16), 'ether'))+" ETH, input: 0x"+self.contract_inputs[step]+")"
                            else:
                                edge["label"] = "Error"
                        elif trace[step]["op"] in ["DELEGATECALL", "STATICCALL"]:
                            if not "error" in trace[step]:
                                edge["label"] = trace[step]["op"]+" (to: "+hex(int(trace[step]["stack"][-2], 16))+", input: 0x"+self.contract_inputs[step]+")"
                            else:
                                edge["label"] = "Error"
                        else:
                            edge["label"] = ""
                        if not edge in self.edges[self.current_basic_block.get_start_address()][self.current_basic_block.get_contract_address()]:
                            self.edges[self.current_basic_block.get_start_address()][self.current_basic_block.get_contract_address()].append(edge)
                self.current_basic_block = None

    def save_control_flow_graph(self, filename, extension):
        colorscheme = ["paleturquoise", "darkseagreen", "wheat", "violet", "deepskyblue", "mediumpurple", "limegreen", "goldenrod", "steelblue"]

        f = open(filename+'.dot', 'w')
        f.write('digraph horus_cfg {\n')
        f.write('rankdir = LR;\n')
        f.write('size = "240"\n')
        f.write('graph[fontname = Courier, fontsize = 14.0, labeljust = l, nojustify = true];node[shape = record];\n')
        legend = {}
        address_width = 10
        for vertice in self.vertices.values():
            for contract in vertice:
                basic_block = vertice[contract]
                if len(hex(list(basic_block.get_instructions().keys())[-1])) > address_width:
                    address_width = len(hex(list(basic_block.get_instructions().keys())[-1]))
        for vertice in self.vertices.values():
            for contract in vertice:
                basic_block = vertice[contract]
                # Draw vertices
                label = '"'+str(contract)+':'+hex(basic_block.get_start_address())+'"[label="'
                for address in basic_block.get_instructions():
                    label += "{0:#0{1}x}".format(address, address_width)+" "+basic_block.get_instructions()[address]+"\l"
                if basic_block.get_depth() == 0:
                    f.write(label+'",style=filled,style=dashed,fillcolor=white];\n')
                else:
                    f.write(label+'",style=filled,fillcolor='+colorscheme[int(contract, 16) % len(colorscheme)]+'];\n')
                if not contract in legend:
                    legend[contract] = colorscheme[int(contract, 16) % len(colorscheme)]
                # Draw edges
                if basic_block.get_start_address() in self.edges:
                    for i in range(len(self.edges[basic_block.get_start_address()][contract])):
                        if self.edges[basic_block.get_start_address()][contract][i]["label"] == "True":
                            f.write('"'+str(contract)+':'+hex(basic_block.get_start_address())+'" -> "'+str(self.edges[basic_block.get_start_address()][contract][i]["contract"])+':'+hex(self.edges[basic_block.get_start_address()][contract][i]["pc"])+'" [label="'+self.edges[basic_block.get_start_address()][contract][i]["label"]+'",color="green"];\n')
                        elif self.edges[basic_block.get_start_address()][contract][i]["label"] == "False":
                            f.write('"'+str(contract)+':'+hex(basic_block.get_start_address())+'" -> "'+str(self.edges[basic_block.get_start_address()][contract][i]["contract"])+':'+hex(self.edges[basic_block.get_start_address()][contract][i]["pc"])+'" [label="'+self.edges[basic_block.get_start_address()][contract][i]["label"]+'",color="red"];\n')
                        else:
                            f.write('"'+str(contract)+':'+hex(basic_block.get_start_address())+'" -> "'+str(self.edges[basic_block.get_start_address()][contract][i]["contract"])+':'+hex(self.edges[basic_block.get_start_address()][contract][i]["pc"])+'" [label="'+self.edges[basic_block.get_start_address()][contract][i]["label"]+'",color="black"];\n')
        # Draw a legend
        f.write('subgraph cluster_legend {\n');
        f.write('label = "Contracts";\n');
        for contract in legend:
            f.write('"'+str(contract)+'"[label="'+str(contract)+'",style=filled,fillcolor='+legend[contract]+'];\n');
        f.write('}\n');
        f.write('}\n')
        f.close()
        if not subprocess.call('dot '+filename+'.dot -T'+extension+' -o '+filename+'.'+extension, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            print("Graphviz is not available. Please install Graphviz from https://www.graphviz.org/download/.")
