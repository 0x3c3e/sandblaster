class NonTerminalNode:
    def __init__(self):
        self.filter_id = None
        self.filter = None
        self.argument_id = None
        self.argument = None
        self.match_offset = None
        self.match = None
        self.unmatch_offset = None
        self.unmatch = None

    def __eq__(self, other):
        return (
            self.filter_id == other.filter_id
            and self.argument_id == other.argument_id
            and self.match_offset == other.match_offset
            and self.unmatch_offset == other.unmatch_offset
        )

    def __str__(self):
        if self.filter:
            return f"({self.filter} {self.argument})"
        return "(%02x %04x %04x %04x)" % (
            self.filter_id,
            self.argument_id,
            self.match_offset,
            self.unmatch_offset,
        )

    def values(self):
        if self.filter:
            return (self.filter, self.argument)
        return ("%02x" % self.filter_id, "%04x" % (self.argument_id))

    def convert_filter(self, convert_fn, f, sandbox_data, keep_builtin_filters):
        (self.filter, self.argument) = convert_fn(
            f, sandbox_data, keep_builtin_filters, self.filter_id, self.argument_id
        )
