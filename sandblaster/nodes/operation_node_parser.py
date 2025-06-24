import struct
from nodes.operation_node import OperationNode
from nodes.terminal_node import TerminalNode


class OperationNodeParser:
    def __init__(self):
        self.cache = {}
        self.operation_nodes = []
        self.flags = []

    def find_operation_node_by_offset(self, offset):
        return self.cache[offset]

    def build_operation_nodes(
        self,
        f,
        num_operation_nodes,
    ):
        for i in range(num_operation_nodes):
            raw = struct.unpack("<8B", f.read(8))
            node = OperationNode(i, raw).parsed_node
            self.operation_nodes.append(node)
            self.cache[node.offset] = node

    def fill_operation_nodes(
        self, sandbox_data, filter_resolver, modifier_resolver, terminal_resolver
    ):
        for op_node in self.operation_nodes:
            op_node.convert_filter(
                sandbox_data, filter_resolver, modifier_resolver, terminal_resolver
            )
            if isinstance(op_node, TerminalNode):
                continue
            if op_node.match_offset in self.cache:
                op_node.match = self.cache[op_node.match_offset]
            if op_node.unmatch_offset in self.cache:
                op_node.unmatch = self.cache[op_node.unmatch_offset]

    def collect_used_flags(self):
        """
        Extracts all unique modifier_flags values from TerminalNodes
        parsed from OperationNode instances.
        """
        self.flags = {
            node.modifier_flags
            for node in self.operation_nodes
            if isinstance(node, TerminalNode)
        }