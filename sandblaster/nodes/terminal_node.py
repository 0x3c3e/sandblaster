from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from nodes.modifier import InlineModifier, Modifier

@dataclass(slots=True)
class TerminalNode:
    # Required (non-default) fields
    type: int
    modifier_flags: int
    modifier: Modifier
    parent: object
    action_inline: bool
    inline_modifier: Optional[InlineModifier]

    # Class-level constants
    TERMINAL_NODE_TYPE_ALLOW = 0x00
    TERMINAL_NODE_TYPE_DENY = 0x01

    # Optional/resolved fields
    flags: Optional[int] = None
    action: Optional[str] = None
    inline_operation_node: Optional[object] = None
    ss: Optional[Any] = None
    operation_name: Optional[str] = None
    parsed: bool = False

    db_modifiers: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: {
        "inline_modifiers": [],
        "flags_modifiers": []
    })

    @classmethod
    def from_raw(cls, parent, raw: bytes) -> "TerminalNode":
        type_ = raw[1] & 1
        modifier_flags = raw[1] | (raw[2] << 8) | (raw[3] << 16)
        action_inline = (modifier_flags & 0x800000) != 0

        inline_modifier = (
            InlineModifier(raw[4], raw[5], raw[6] + (raw[7] << 8))
            if action_inline else None
        )

        modifier = Modifier(modifier_flags, raw[4], raw[5], raw[6] + (raw[7] << 8))

        return cls(
            type=type_,
            modifier_flags=modifier_flags,
            modifier=modifier,
            parent=parent,
            action_inline=action_inline,
            inline_modifier=inline_modifier,
        )

    def __eq__(self, other):
        return self.type == other.type and self.flags == other.flags

    def __str__(self):
        parts = ["allow" if self.is_allow() else "deny" if self.is_deny() else "unknown"]

        if self.parsed:
            if self.action_inline and self.inline_modifier:
                if not self.inline_modifier.policy_op_idx:
                    for mod in self.db_modifiers["inline_modifiers"]:
                        parts.append(f"(with {mod['name']} {self.ss})")
                else:
                    parts.append(str(self.inline_operation_node))
            for mod in self.db_modifiers["flags_modifiers"]:
                if mod and "name" in mod:
                    parts.append(f"(with {mod['name']})")

        return " ".join(parts)

    def convert_filter(self, sandbox_data, filter_resolver, modifier_resolver, terminal_resolver):
        if self.inline_modifier:
            if not self.inline_modifier.policy_op_idx:
                self.db_modifiers["inline_modifiers"].append(
                    terminal_resolver.get_modifier(self.inline_modifier.id)
                )
                self.ss = modifier_resolver.resolve(
                    self.inline_modifier.id,
                    self.inline_modifier.argument,
                )
            else:
                self.operation_name = sandbox_data.sb_ops[self.inline_modifier.policy_op_idx]
                self.inline_operation_node = sandbox_data.operation_nodes[
                    sandbox_data.policies[self.inline_modifier.argument]
                ]

        self.db_modifiers["flags_modifiers"].extend(
            terminal_resolver.get_modifiers_by_flag(
                self.modifier.flags, self.is_deny(), self.is_allow()
            )
        )
        self.parsed = True

    def is_allow(self) -> bool:
        return self.type == self.TERMINAL_NODE_TYPE_ALLOW

    def is_deny(self) -> bool:
        return self.type == self.TERMINAL_NODE_TYPE_DENY
