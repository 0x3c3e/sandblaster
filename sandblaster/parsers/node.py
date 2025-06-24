from typing import Union
from enum import IntEnum
from nodes.terminal import TerminalNode
from nodes.non_terminal import NonTerminalNode


class NodeType(IntEnum):
    NON_TERMINAL = 0x00
    TERMINAL = 0x01


class NodeParser:
    def __init__(self):
        self.cache = {}
        self.flags = []

    def find_operation_node_by_offset(self, offset):
        return self.cache[offset]

    def parse_operation_node(
        self, offset: int, raw: bytes
    ) -> Union[TerminalNode, NonTerminalNode]:
        node_type = NodeType(raw[0])

        if node_type == NodeType.TERMINAL:
            return TerminalNode.from_raw(offset, raw)
        return NonTerminalNode.from_raw(offset, raw)

    def build_operation_nodes(
        self,
        f,
        num_operation_nodes,
    ):
        for i in range(num_operation_nodes):
            self.cache[i] = self.parse_operation_node(i, f.read(8))

    def fill_operation_nodes(
        self, sandbox_data, filter_resolver, modifier_resolver, terminal_resolver
    ):
        for op_node in self.cache.values():
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
            for node in self.cache.values()
            if isinstance(node, TerminalNode)
        }
