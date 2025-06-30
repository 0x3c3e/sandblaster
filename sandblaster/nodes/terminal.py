from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from functools import cached_property
from enum import IntEnum


class NodeType(IntEnum):
    ALLOW = 0x00
    DENY = 0x01

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class TerminalNode:
    offset: int
    raw: bytes

    flags: Optional[int] = None
    action: Optional[str] = None
    inline_operation_node: Optional[object] = None
    ss: Optional[Any] = None
    operation_name: Optional[str] = None
    inline_modifiers: Dict[str, Any] = field(default_factory=dict)
    flags_modifiers: List[Dict[str, Any]] = field(default_factory=list)

    _str_repr: Optional[str] = field(init=False, default=None)

    @classmethod
    def from_raw(cls, offset: int, raw: bytes) -> "TerminalNode":
        return cls(offset=offset, raw=raw)

    @cached_property
    def modifier_flags(self) -> int:
        return self.raw[1] | (self.raw[2] << 8) | (self.raw[3] << 16)

    @cached_property
    def action_inline(self) -> bool:
        return bool(self.modifier_flags & 0x800000)

    @cached_property
    def arg_type(self) -> int:
        return self.raw[4]

    @cached_property
    def arg_id(self) -> int:
        return self.raw[5]

    @cached_property
    def arg_value(self) -> int:
        return self.raw[6] | (self.raw[7] << 8)

    @cached_property
    def type(self) -> int:
        return NodeType(self.raw[1] & 1)

    def convert_filter(
        self,
        sandbox_data,
        filter_resolver,
        modifier_resolver,
        terminal_resolver,
    ):
        if self.action_inline:
            if not self.arg_id:
                self.inline_modifiers = terminal_resolver.get_modifier(self.arg_type)
                self.ss = modifier_resolver.resolve(self.arg_type, self.arg_value)
            else:
                self.operation_name = sandbox_data.sb_ops[self.arg_id]
                op_idx = sandbox_data.policies[self.arg_value]
                self.inline_operation_node = sandbox_data.operation_nodes[op_idx]

        self.flags_modifiers = terminal_resolver.get_modifiers_by_flag(
            self.modifier_flags
        )
        self._str_repr = self._build_str_repr()

    def _build_str_repr(self) -> str:
        parts = [str(self.type)]

        if self.action_inline:
            if not self.arg_id and self.inline_modifiers:
                name = self.inline_modifiers["name"]
                parts.append(f"(with {name} {self.ss})")
            elif self.inline_operation_node:
                parts.append(str(self.inline_operation_node))

        for mod in self.flags_modifiers:
            name = mod["name"]
            parts.append(f"(with {name})")

        return " ".join(parts)

    def __str__(self) -> str:
        return self._str_repr

    def __hash__(self):
        return hash(self.offset)
