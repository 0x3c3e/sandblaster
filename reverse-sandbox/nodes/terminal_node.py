import os
import json
import sandbox_filter


class TerminalNode:
    TERMINAL_NODE_TYPE_ALLOW = 0x00
    TERMINAL_NODE_TYPE_DENY = 0x01

    INLINE_MODIFIERS = "inline_modifiers"
    FLAGS_MODIFIERS = "flags_modifiers"

    @staticmethod
    def load_modifiers_db():
        script_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(script_dir, "misc/modifiers.json")) as data:
            temp = json.load(data)
        return temp["modifiers"]

    modifiers_db = load_modifiers_db()

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

    def get_modifier(self, key_value, key_name):
        for i in self.modifiers_db:
            if i[key_name] == key_value:
                return i

    def get_modifiers_by_flag(self, flags):
        modifiers = []
        for modifier in self.modifiers_db:
            # should be if modifier['action_mask'] ... currently ignoring 'no-report' modifier
            if modifier["action_mask"] and (
                flags & modifier["action_mask"] == modifier["action_flag"]
            ):
                # remove default with report
                if (
                    modifier["name"] == "report" and self.is_deny()
                ):  # report is default for deny
                    continue
                if (
                    modifier["name"] == "no-report" and self.is_allow()
                ):  # report is default for allow
                    continue
                # need to add no-report
                modifiers.append(modifier)

        return modifiers

    def terminal_convert_function(
        self, convert_fn, infile, sandbox_data, keep_builtin_filters
    ):
        if self.inline_modifier:
            if not self.inline_modifier.policy_op_idx:
                self.db_modifiers[self.INLINE_MODIFIERS].append(
                    self.get_modifier(self.inline_modifier.id, "id")
                )
                self.ss = sandbox_filter.convert_modifier_callback(
                    infile,
                    sandbox_data,
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
            self.get_modifiers_by_flag(self.modifier.flags)
        )
        self.parsed = True

    def convert_filter(self, convert_fn, f, sandbox_data, keep_builtin_filters):
        self.terminal_convert_function(
            convert_fn, f, sandbox_data, keep_builtin_filters
        )

    def is_allow(self):
        return self.type == self.TERMINAL_NODE_TYPE_ALLOW

    def is_deny(self):
        return self.type == self.TERMINAL_NODE_TYPE_DENY
