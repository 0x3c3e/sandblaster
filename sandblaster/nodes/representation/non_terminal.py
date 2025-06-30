class NonTerminalRepresentation:
    def __init__(self, node, filter_resolver):
        self.filter, self.argument = filter_resolver.resolve(
            node.filter_id, node.argument_id
        )

    def __str__(self):
        return f"({self.filter} {self.argument})"
