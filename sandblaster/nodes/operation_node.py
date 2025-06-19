from nodes.terminal_node import TerminalNode
from nodes.non_terminal_node import NonTerminalNode


class InlineModifier:
    def __init__(self, id, policy_op_idx, argument):
        self.id = id
        self.policy_op_idx = policy_op_idx
        self.argument = argument


class Modifier:
    def __init__(self, flags, count, unknown, offset):
        self.flags = flags
        self.count = count
        self.unknown = unknown
        self.offset = offset


class OperationNode:
    OPERATION_NODE_TYPE_NON_TERMINAL = 0x00
    OPERATION_NODE_TYPE_TERMINAL = 0x01

    def __init__(self, offset, raw):
        self.offset = offset
        self.raw = raw
        self.type = None
        self.node = None

    def is_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_TERMINAL

    def is_non_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_NON_TERMINAL

    def parse_terminal(self):
        self.node = TerminalNode()
        self.node.parent = self

        self.node.type = self.raw[1] & 1

        self.node.modifier_flags = (
            self.raw[1] | (self.raw[2] << 8) | (self.raw[3] << 16)
        )
        self.node.action_inline = self.node.modifier_flags & 0x800000 != 0

        if self.node.action_inline:
            self.node.inline_modifier = InlineModifier(
                self.raw[4], self.raw[5], self.raw[6] + (self.raw[7] << 8)
            )

        self.node.modifier = Modifier(
            self.node.modifier_flags,
            self.raw[4],
            self.raw[5],
            self.raw[6] + (self.raw[7] << 8),
        )

    def parse_non_terminal(self):
        self.node = NonTerminalNode()
        self.node.parent = self
        self.node.filter_id = self.raw[1]
        self.node.argument_id = self.raw[2] + (self.raw[3] << 8)
        self.node.match_offset = self.raw[4] + (self.raw[5] << 8)
        self.node.unmatch_offset = self.raw[6] + (self.raw[7] << 8)

    def parse_raw(self):
        self.type = self.raw[0]
        if self.is_terminal():
            self.parse_terminal()
        elif self.is_non_terminal():
            self.parse_non_terminal()

    def convert_filter(self, f, sandbox_data):
        self.node.convert_filter(f, sandbox_data)

    def __str__(self):
        return str(self.node)

    def values(self):
        if self.is_terminal():
            return (None, None)
        else:
            return self.node.values()

    def __eq__(self, other):
        return self.offset == other.offset

    def __hash__(self):
        return hash(self.offset)
