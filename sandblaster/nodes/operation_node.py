from dataclasses import dataclass
from typing import Union
from enum import IntEnum
from nodes.terminal_node import TerminalNode
from nodes.non_terminal_node import NonTerminalNode


class NodeType(IntEnum):
    NON_TERMINAL = 0x00
    TERMINAL = 0x01


@dataclass(slots=True)
class OperationNode:
    offset: int
    raw: bytes

    @property
    def type(self) -> NodeType:
        return NodeType(self.raw[0])

    def is_terminal(self) -> bool:
        return self.type == NodeType.TERMINAL

    def is_non_terminal(self) -> bool:
        return self.type == NodeType.NON_TERMINAL

    @property
    def parsed_node(self) -> Union[TerminalNode, NonTerminalNode]:
        if self.is_terminal():
            return TerminalNode.from_raw(self.offset, self.raw)
        elif self.is_non_terminal():
            return NonTerminalNode.from_raw(self.offset, self.raw)
        else:
            raise ValueError(f"Unknown node type: {self.type:#x}")

    def __hash__(self):
        return hash(self.offset)

    def __repr__(self):
        return f"<OperationNode offset={self.offset:#x} type={self.type.name}>"
