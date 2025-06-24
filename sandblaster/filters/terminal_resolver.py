from collections import defaultdict


class TerminalResolver:
    def __init__(self, modifiers, used_flags: set[int]):
        self._modifiers_by_id = modifiers._filters
        self._modifiers_by_name = {m["name"]: m for m in self._modifiers_by_id.values()}
        self._modifiers_by_flags_context = defaultdict(list)

        for m in self._modifiers_by_id.values():
            mask = m["action_mask"]
            if not mask:
                continue
            flag = m["action_flag"]

            for f in used_flags:
                if (f & mask) == flag:
                    self._modifiers_by_flags_context[f].append(m)

    def get_modifier(self, id: int) -> dict:
        return self._modifiers_by_id[id]

    def get_modifier_by_name(self, name: str) -> dict:
        return self._modifiers_by_name.get(name)

    def get_modifiers_by_flag(self, flags: int) -> list[dict]:
        return self._modifiers_by_flags_context[flags]
