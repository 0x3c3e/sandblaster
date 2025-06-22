class TerminalNode:
    TERMINAL_NODE_TYPE_ALLOW = 0x00
    TERMINAL_NODE_TYPE_DENY = 0x01

    INLINE_MODIFIERS = "inline_modifiers"
    FLAGS_MODIFIERS = "flags_modifiers"

    def __init__(self):
        self.type = None
        self.flags = None
        self.action = None
        self.modifier_flags = None
        self.action_inline = None
        self.inline_modifier = None
        self.modifier = None
        self.inline_operation_node = None
        self.ss = None
        self.db_modifiers = {self.INLINE_MODIFIERS: [], self.FLAGS_MODIFIERS: []}
        self.parsed = False
        self.operation_name = None

    def __eq__(self, other):
        return self.type == other.type and self.flags == other.flags

    def __str__(self):
        ret = ""
        if self.type == self.TERMINAL_NODE_TYPE_ALLOW:
            ret += "allow"
        elif self.type == self.TERMINAL_NODE_TYPE_DENY:
            ret += "deny"
        else:
            ret += "unknown"

        if self.parsed:
            if self.action_inline:
                if not self.inline_modifier.policy_op_idx:
                    for modifier in self.db_modifiers[self.INLINE_MODIFIERS]:
                        ret += f" (with {modifier['name']} {self.ss})"
                else:
                    ret += str(self.inline_operation_node)
        for modifier in self.db_modifiers[self.FLAGS_MODIFIERS]:
            if modifier and "name" in modifier.keys():
                ret += f" (with {modifier['name']})"

        return ret

    def convert_filter(
        self, sandbox_data, filter_resolver, modifier_resolver, terminal_resolver
    ):
        if self.inline_modifier:
            if not self.inline_modifier.policy_op_idx:
                self.db_modifiers[self.INLINE_MODIFIERS].append(
                    terminal_resolver.get_modifier(self.inline_modifier.id)
                )
                self.ss = modifier_resolver.resolve(
                    self.inline_modifier.id,
                    self.inline_modifier.argument,
                )
            else:
                self.operation_name = sandbox_data.sb_ops[
                    self.inline_modifier.policy_op_idx
                ]
                self.inline_operation_node = sandbox_data.operation_nodes[
                    sandbox_data.policies[self.inline_modifier.argument]
                ]
        self.db_modifiers[self.FLAGS_MODIFIERS].extend(
            terminal_resolver.get_modifiers_by_flag(
                self.modifier.flags, self.is_deny(), self.is_allow()
            )
        )
        self.parsed = True

    def is_allow(self):
        return self.type == self.TERMINAL_NODE_TYPE_ALLOW

    def is_deny(self):
        return self.type == self.TERMINAL_NODE_TYPE_DENY
