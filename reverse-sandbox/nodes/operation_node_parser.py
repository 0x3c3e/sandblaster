import struct
from nodes.operation_node import OperationNode


class OperionNodeParser:
    def __init__(self):
        self.cache = {}
        self.operation_nodes = []

    def find_operation_node_by_offset(self, offset):
        return self.cache[offset]

    def build_operation_node(self, raw, index):
        node = OperationNode(index, raw)
        node.parse_raw()
        return node

    def build_operation_nodes(self, f, num_operation_nodes):
        for i in range(num_operation_nodes):
            raw = struct.unpack("<8B", f.read(8))
            node = self.build_operation_node(raw, i)
            self.operation_nodes.append(node)
            self.cache[node.offset] = node
        for op_node in self.operation_nodes:
            if not op_node.is_non_terminal():
                continue
            if op_node.non_terminal.match_offset in self.cache:
                op_node.non_terminal.match = self.cache[
                    op_node.non_terminal.match_offset
                ]
            if op_node.non_terminal.unmatch_offset in self.cache:
                op_node.non_terminal.unmatch = self.cache[
                    op_node.non_terminal.unmatch_offset
                ]
