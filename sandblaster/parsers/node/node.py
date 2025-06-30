from enum import IntEnum
from typing import Union

from sandblaster.nodes.non_terminal import NonTerminalNode
from sandblaster.nodes.terminal import TerminalNode


class NodeType(IntEnum):
    NON_TERMINAL = 0x00
    TERMINAL = 0x01


class NodeParser:
    def _parse_operation_node(
        self, offset: int, raw: bytes
    ) -> Union[TerminalNode, NonTerminalNode]:
        node_type = NodeType(raw[0])

        if node_type == NodeType.TERMINAL:
            return TerminalNode.from_raw(offset, raw)
        return NonTerminalNode.from_raw(offset, raw)

    def parse(
        self,
        f,
        num_operation_nodes,
    ):
        nodes = {}
        flags = set()
        for i in range(num_operation_nodes):
            node = self._parse_operation_node(i, f.read(8))
            nodes[i] = node
            if isinstance(node, TerminalNode):
                flags.add(node.modifier_flags)
        return nodes, flags
