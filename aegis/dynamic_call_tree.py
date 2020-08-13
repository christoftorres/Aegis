#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class DynamicCallTree:
    def __init__(self):
        self.call_dependencies = {}

    def check_call_dependency(self, source, sink):
        if not self.call_dependencies[sink]:
            return False
        if source == self.call_dependencies[sink]:
            return True
        return self.check_call_dependency(source, self.call_dependencies[sink])

    def execute(self, trace, step):
        if len(self.call_dependencies) == 0 or not step-1 in trace or trace[step]["transaction"] != trace[step-1]["transaction"]:
            self.call_dependencies[step] = None
        elif trace[step]["depth"] > trace[step-1]["depth"]:
            self.call_dependencies[step] = step - 1
        elif trace[step]["depth"] < trace[step-1]["depth"]:
            self.call_dependencies[step] = self.call_dependencies[self.call_dependencies[step-1]]
        else:
            self.call_dependencies[step] = self.call_dependencies[step-1]
