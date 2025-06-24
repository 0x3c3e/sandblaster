import networkx as nx
from networkx.drawing.nx_pydot import write_dot
from nodes.terminal import TerminalNode


class GraphParser:
    def __init__(self, node):
        self.graph = nx.DiGraph()
        self.graph.add_node(node.offset, start=True)
        self.nodes_to_process = {node}
        self.node = None
        self.duplicates = {}

    def add_new_node(self):
        key = (self.node.filter_id, self.node.argument_id)
        duplicate = False
        label = self.node.offset
        color = "black"
        if key not in self.duplicates:
            self.duplicates[key] = self.node.offset
        else:
            label = self.duplicates[key]
            duplicate = True
            color = "green"
        self.graph.add_node(
            self.node.offset, duplicate=duplicate, label=label, color=color
        )

    def add_path(self, reverse: bool) -> None:
        if reverse:
            match_node = self.node.unmatch
            edge_style = "dashed"
            result = 0
        else:
            match_node = self.node.match
            edge_style = "solid"
            result = 1
        if not match_node:
            return
        self.graph.add_node(match_node.offset)
        if isinstance(match_node, TerminalNode):
            self.graph.nodes[match_node.offset]["end"] = True
            self.graph.nodes[match_node.offset]["color"] = "blue"
            self.graph.nodes[match_node.offset]["label"] = match_node.offset
        self.graph.add_edge(
            self.node.offset, match_node.offset, style=edge_style, result=result
        )
        self.nodes_to_process.add(match_node)

    def decide_and_add_paths(self) -> None:
        non_terminal = self.node
        match_is_terminal = isinstance(non_terminal.match, TerminalNode)
        unmatch_is_terminal = isinstance(non_terminal.unmatch, TerminalNode)
        if not match_is_terminal and not unmatch_is_terminal:
            self.add_path(False)
            self.add_path(True)
        elif not match_is_terminal and unmatch_is_terminal:
            self.add_path(non_terminal.unmatch.is_allow)
            self.add_path(not non_terminal.unmatch.is_allow)
        elif match_is_terminal and not unmatch_is_terminal:
            self.add_path(non_terminal.match.is_allow)
            self.add_path(not non_terminal.match.is_allow)
        elif match_is_terminal and unmatch_is_terminal:
            self.add_path(True)
            self.add_path(False)

    def build_operation_node_graph(self):
        while self.nodes_to_process:
            self.node = self.nodes_to_process.pop()
            if isinstance(self.node, TerminalNode):
                continue
            self.add_new_node()
            self.decide_and_add_paths()
        return self.graph

    def export_dot(self, filename):
        write_dot(self.graph, filename)
