class TerminalNodeRepresentation:
    def __init__(self, node, terminal_resolver, modifier_resolver, sandbox_data):
        if node.action_inline:
            if not node.arg_id:
                self.inline_modifiers = terminal_resolver.get_modifier(node.arg_type)
                self.inline_data = modifier_resolver.resolve(
                    node.arg_type, node.arg_value
                )
            else:
                op_idx = sandbox_data.policies[node.arg_value]
                self.inline_operation_node = sandbox_data.operation_nodes[op_idx]

        self.flags_modifiers = terminal_resolver.get_modifiers_by_flag(
            node.modifier_flags
        )
        self.node = node

    def __str__(self) -> str:
        parts = [str(self.node.type)]

        if self.node.action_inline:
            if self.inline_modifiers:
                name = self.inline_modifiers["name"]
                parts.append(f"(with {name} {self.inline_data})")
            elif self.inline_operation_node:
                parts.append(str(self.inline_operation_node))

        for mod in self.flags_modifiers:
            name = mod["name"]
            parts.append(f"(with {name})")

        return " ".join(parts)
