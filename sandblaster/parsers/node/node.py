from typing import Union
from enum import IntEnum
from nodes.terminal import TerminalNode
from nodes.non_terminal import NonTerminalNode


class NodeType(IntEnum):
    NON_TERMINAL = 0x00
    TERMINAL = 0x01


class NodeParser:
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
        nodes = {}
        for i in range(num_operation_nodes):
            nodes[i] = self.parse_operation_node(i, f.read(8))
        return nodes
