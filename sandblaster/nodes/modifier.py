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
