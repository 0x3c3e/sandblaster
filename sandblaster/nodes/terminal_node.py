from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from nodes.modifier import InlineModifier, Modifier


@dataclass(slots=True)
class TerminalNode:
    offset: int
    raw: bytes

    # Constants
    TERMINAL_NODE_TYPE_ALLOW = 0x00
    TERMINAL_NODE_TYPE_DENY = 0x01

    # Resolved fields (set later by convert_filter)
    flags: Optional[int] = None
    action: Optional[str] = None
    inline_operation_node: Optional[object] = None
    ss: Optional[Any] = None
    operation_name: Optional[str] = None
    inline_modifiers: Dict[str, Any] = field(default_factory=dict)
    flags_modifiers: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_raw(cls, offset: int, raw: bytes) -> "TerminalNode":
        return cls(offset=offset, raw=raw)

    @property
    def modifier_flags(self) -> int:
        return self.raw[1] | (self.raw[2] << 8) | (self.raw[3] << 16)

    @property
    def action_inline(self) -> bool:
        return bool(self.modifier_flags & 0x800000)

    @property
    def arg_type(self) -> int:
        return self.raw[4]

    @property
    def arg_id(self) -> int:
        return self.raw[5]

    @property
    def arg_value(self) -> int:
        return self.raw[6] | (self.raw[7] << 8)

    @property
    def inline_modifier(self) -> Optional[InlineModifier]:
        if self.action_inline:
            return InlineModifier(self.arg_type, self.arg_id, self.arg_value)
        return None

    @property
    def modifier(self) -> Modifier:
        return Modifier(self.modifier_flags, self.arg_type, self.arg_id, self.arg_value)

    @property
    def type(self) -> int:
        return self.modifier_flags & 1

    def is_allow(self) -> bool:
        return self.type == self.TERMINAL_NODE_TYPE_ALLOW

    def is_deny(self) -> bool:
        return self.type == self.TERMINAL_NODE_TYPE_DENY

    def convert_filter(
        self,
        sandbox_data,
        filter_resolver,
        modifier_resolver,
        terminal_resolver,
    ):
        inline = self.inline_modifier
        if inline:
            if not inline.policy_op_idx:
                self.inline_modifiers = terminal_resolver.get_modifier(inline.id)
                self.ss = modifier_resolver.resolve(inline.id, inline.argument)
            else:
                self.operation_name = sandbox_data.sb_ops[inline.policy_op_idx]
                op_idx = sandbox_data.policies[inline.argument]
                self.inline_operation_node = sandbox_data.operation_nodes[op_idx]

        self.flags_modifiers = terminal_resolver.get_modifiers_by_flag(
            self.modifier.flags
        )

    def __hash__(self):
        return hash(self.offset)
    
    def __str__(self):
        parts = ["allow" if self.is_allow() else "deny" if self.is_deny() else "unknown"]

        inline = self.inline_modifier
        if self.action_inline and inline:
            if not inline.policy_op_idx and self.inline_modifiers:
                parts.append(f"(with {self.inline_modifiers.get('name')} {self.ss})")
            elif self.inline_operation_node:
                parts.append(str(self.inline_operation_node))

        for mod in self.flags_modifiers or []:
            name = mod.get("name")
            if name:
                parts.append(f"(with {name})")

        return " ".join(parts)
