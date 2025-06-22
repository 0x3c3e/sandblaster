class TerminalResolver:
    def __init__(self, modifiers):
        self.modifiers = modifiers

    def get_modifiers_by_flag(self, flags, deny, allow):
        modifiers = []
        for modifier in self.modifiers._filters.values():
            # should be if modifier['action_mask'] ... currently ignoring 'no-report' modifier
            if modifier["action_mask"] and (
                flags & modifier["action_mask"] == modifier["action_flag"]
            ):
                # remove default with report
                if modifier["name"] == "report" and deny:  # report is default for deny
                    continue
                if (
                    modifier["name"] == "no-report" and allow
                ):  # report is default for allow
                    continue
                # need to add no-report
                modifiers.append(modifier)
        return modifiers

    def get_modifier(self, id):
        return self.modifiers._filters[id]
