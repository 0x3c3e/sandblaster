from nodes.terminal import TerminalNode


class NodeGraph:
    def __init__(self, nodes):
        self.nodes = nodes
        self.flags = self.collect_used_flags()

    def find_operation_node_by_offset(self, offset):
        return self.nodes[offset]

    def link(self):
        for op_node in self.nodes.values():
            if isinstance(op_node, TerminalNode):
                continue
            op_node.match = self.nodes[op_node.match_offset]
            op_node.unmatch = self.nodes[op_node.unmatch_offset]

    def convert(
        self, sandbox_data, filter_resolver, modifier_resolver, terminal_resolver
    ):
        for op_node in self.nodes.values():
            op_node.convert_filter(
                sandbox_data, filter_resolver, modifier_resolver, terminal_resolver
            )

    def collect_used_flags(self):
        self.flags = {
            node.modifier_flags
            for node in self.nodes.values()
            if isinstance(node, TerminalNode)
        }
