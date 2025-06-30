import networkx as nx

from sandblaster.nodes.terminal import NodeType, TerminalNode


class GraphParser:
    def __init__(self, node):
        self.graph = nx.DiGraph()
        self.graph.add_node(node.offset)
        self.nodes_to_process = {node}
        self.node = None

    def get_nodes_attributes(self, reverse: bool):
        if reverse:
            return (self.node.unmatch, "dashed", 0)
        return (self.node.match, "solid", 1)

    def add_path(self, reverse: bool) -> None:
        match_node, edge_style, result = self.get_nodes_attributes(reverse)
        if not match_node:
            return
        self.graph.add_node(match_node.offset)
        self.graph.add_edge(
            self.node.offset, match_node.offset, style=edge_style, result=result
        )
        self.nodes_to_process.add(match_node)

    def link_nodes(self) -> None:
        match_is_terminal = isinstance(self.node.match, TerminalNode)
        unmatch_is_terminal = isinstance(self.node.unmatch, TerminalNode)
        if not match_is_terminal and not unmatch_is_terminal:
            self.add_path(False)
            self.add_path(True)
        elif not match_is_terminal and unmatch_is_terminal:
            self.add_path(self.node.unmatch.type == NodeType.ALLOW)
            self.add_path(self.node.unmatch.type == NodeType.DENY)
        elif match_is_terminal and not unmatch_is_terminal:
            self.add_path(self.node.match.type == NodeType.ALLOW)
            self.add_path(self.node.match.type == NodeType.DENY)
        elif match_is_terminal and unmatch_is_terminal:
            self.add_path(True)
            self.add_path(False)

    def parse(self):
        while self.nodes_to_process:
            self.node = self.nodes_to_process.pop()
            if isinstance(self.node, TerminalNode):
                continue
            self.graph.add_node(self.node.offset)
            self.link_nodes()
        return self.graph
