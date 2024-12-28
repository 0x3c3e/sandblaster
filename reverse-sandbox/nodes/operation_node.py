#!/usr/bin/python3

import logging
import logging.config
from nodes.terminal_node import TerminalNode
from nodes.non_terminal_node import NonTerminalNode

logger = logging.getLogger(__name__)


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
    """A rule item in the binary sandbox profile

    It may either be a teminal node (end node) or a non-terminal node
    (intermediary node). Each node type uses another class, as defined
    above.
    """

    OPERATION_NODE_TYPE_NON_TERMINAL = 0x00
    OPERATION_NODE_TYPE_TERMINAL = 0x01

    def __init__(self, offset, raw):
        self.offset = offset
        self.raw = raw
        self.type = None
        self.terminal = None
        self.non_terminal = None

    def is_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_TERMINAL

    def is_non_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_NON_TERMINAL

    def parse_terminal(self):
        # end node
        self.terminal = TerminalNode()
        self.terminal.parent = self

        self.terminal.type = self.raw[1] & 1

        self.terminal.modifier_flags = (
            self.raw[1] | (self.raw[2] << 8) | (self.raw[3] << 16)
        )
        self.terminal.action_inline = self.terminal.modifier_flags & 0x800000 != 0

        if self.terminal.action_inline:
            self.terminal.inline_modifier = InlineModifier(
                self.raw[4], self.raw[5], self.raw[6] + (self.raw[7] << 8)
            )

        self.terminal.modifier = Modifier(
            self.terminal.modifier_flags,
            self.raw[4],
            self.raw[5],
            self.raw[6] + (self.raw[7] << 8),
        )

    def parse_non_terminal(self):
        # intermediary node
        self.non_terminal = NonTerminalNode()
        self.non_terminal.parent = self
        self.non_terminal.filter_id = self.raw[1]
        self.non_terminal.argument_id = self.raw[2] + (self.raw[3] << 8)
        self.non_terminal.match_offset = self.raw[4] + (self.raw[5] << 8)
        self.non_terminal.unmatch_offset = self.raw[6] + (self.raw[7] << 8)

    def parse_raw(self):
        self.type = self.raw[0]
        if self.is_terminal():
            self.parse_terminal()
        elif self.is_non_terminal():
            self.parse_non_terminal()

    def convert_filter(self, convert_fn, f, sandbox_data, keep_builtin_filters):
        if self.is_non_terminal():
            self.non_terminal.convert_filter(
                convert_fn, f, sandbox_data, keep_builtin_filters
            )
        elif self.terminal:
            self.terminal.convert_filter(
                self.terminal.terminal_convert_function,
                f,
                sandbox_data,
                keep_builtin_filters,
            )

    def __str__(self):
        ret = ""
        if self.is_terminal():
            ret += str(self.terminal)
        if self.is_non_terminal():
            ret += str(self.non_terminal)
        return ret

    def values(self):
        if self.is_terminal():
            return (None, None)
        else:
            return self.non_terminal.values()

    def __eq__(self, other):
        return self.offset == other.offset

    def __hash__(self):
        return hash(self.offset)
