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

    def build_operation_nodes(
        self, f, num_operation_nodes, sandbox_data, filter_resolver, modifier_resolver
    ):
        for i in range(num_operation_nodes):
            raw = struct.unpack("<8B", f.read(8))
            node = self.build_operation_node(raw, i)
            self.operation_nodes.append(node)
            self.cache[node.offset] = node
        for op_node in self.operation_nodes:
            op_node.convert_filter(
                sandbox_data,
                filter_resolver,
                modifier_resolver,
            )
            if not op_node.is_non_terminal():
                continue
            if op_node.node.match_offset in self.cache:
                op_node.node.match = self.cache[op_node.node.match_offset]
            if op_node.node.unmatch_offset in self.cache:
                op_node.node.unmatch = self.cache[op_node.node.unmatch_offset]
