import networkx as nx

from sandblaster.nodes.terminal import NodeType, TerminalNode


class GraphParser:
    def __init__(self, node):
        self.graph = nx.DiGraph()
        self.nodes_to_process = {node}

    def get_nodes_attributes(self, node, reverse: bool):
        if reverse:
            return (node.unmatch, "dashed", 0)
        return (node.match, "solid", 1)

    def add_path(self, node, reverse: bool) -> None:
        match_node, edge_style, result = self.get_nodes_attributes(node, reverse)
        if not match_node:
            return
        self.graph.add_node(match_node.offset, id=(node.filter_id, node.argument_id))
        self.graph.add_edge(
            node.offset, match_node.offset, style=edge_style, result=result
        )
        self.nodes_to_process.add(match_node)

    def link_node(self, node) -> None:
        match = node.match
        unmatch = node.unmatch
        match_terminal = isinstance(match, TerminalNode)
        unmatch_terminal = isinstance(unmatch, TerminalNode)

        if not match_terminal:
            self.add_path(node, False)
        if not unmatch_terminal:
            self.add_path(node, True)

        if match_terminal:
            self.add_path(node, match.type == NodeType.DENY)
        if unmatch_terminal:
            self.add_path(node, unmatch.type == NodeType.ALLOW)

    def parse(self):
        while self.nodes_to_process:
            node = self.nodes_to_process.pop()
            if isinstance(node, TerminalNode):
                continue
            self.graph.add_node(node.offset, id=(node.filter_id, node.argument_id))
            self.link_node(node)
        return self.graph
