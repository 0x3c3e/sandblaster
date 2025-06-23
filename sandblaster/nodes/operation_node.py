from dataclasses import dataclass
from typing import Union
from nodes.terminal_node import TerminalNode
from nodes.non_terminal_node import NonTerminalNode


@dataclass(slots=True)
class OperationNode:
    offset: int
    raw: bytes
    node: Union[TerminalNode, NonTerminalNode, None] = None

    OPERATION_NODE_TYPE_NON_TERMINAL = 0x00
    OPERATION_NODE_TYPE_TERMINAL = 0x01

    @property
    def type(self):
        return self.raw[0]

    def is_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_TERMINAL

    def is_non_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_NON_TERMINAL

    def parse_raw(self):
        match self.type:
            case self.OPERATION_NODE_TYPE_TERMINAL:
                self.node = TerminalNode.from_raw(self, self.raw)
            case self.OPERATION_NODE_TYPE_NON_TERMINAL:
                self.node = NonTerminalNode.from_raw(self, self.raw)
            case _:
                raise ValueError(f"Unknown node type: {self.type:#x}")

    def convert_filter(self, sandbox_data, filter_resolver, modifier_resolver, terminal_resolver):
        self.node.convert_filter(sandbox_data, filter_resolver, modifier_resolver, terminal_resolver)

    def __str__(self):
        return str(self.node)
    
    def __hash__(self):
        return hash(self.offset)
