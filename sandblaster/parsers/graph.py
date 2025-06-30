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
        self.graph.add_node(match_node.offset)
        self.graph.add_edge(
            node.offset, match_node.offset, style=edge_style, result=result
        )
        self.nodes_to_process.add(match_node)

    def link_node(self, node) -> None:
        match_is_terminal = isinstance(node.match, TerminalNode)
        unmatch_is_terminal = isinstance(node.unmatch, TerminalNode)
        if not match_is_terminal and not unmatch_is_terminal:
            self.add_path(node, False)
            self.add_path(node, True)
        elif not match_is_terminal and unmatch_is_terminal:
            self.add_path(node, node.unmatch.type == NodeType.ALLOW)
            self.add_path(node, node.unmatch.type == NodeType.DENY)
        elif match_is_terminal and not unmatch_is_terminal:
            self.add_path(node, node.match.type == NodeType.ALLOW)
            self.add_path(node, node.match.type == NodeType.DENY)
        elif match_is_terminal and unmatch_is_terminal:
            self.add_path(node, True)
            self.add_path(node, False)

    def parse(self):
        while self.nodes_to_process:
            node = self.nodes_to_process.pop()
            if isinstance(node, TerminalNode):
                continue
            self.graph.add_node(node.offset)
            self.link_node(node)
        return self.graph
