class NonTerminalRepresentation:
    def __init__(self, filter_id, argument_id, filter_resolver):
        self.filter, self.argument = filter_resolver.resolve(filter_id, argument_id)

    def __str__(self):
        return f"({self.filter} {self.argument})"
