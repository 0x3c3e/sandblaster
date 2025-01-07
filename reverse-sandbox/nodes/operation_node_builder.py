import logging
import networkx as nx

logger = logging.getLogger(__name__)

import networkx as nx


class OperationNodeGraphBuilder:
    def __init__(self, node):
        self.graph = nx.DiGraph()
        self.graph.add_node(node.offset, start=True, color="red")
        self.nodes_to_process = {node}
        self.node = None

    def add_path(self, reverse: bool) -> None:
        if reverse:
            match_node = self.node.non_terminal.unmatch
            edge_style = "dashed"
        else:
            match_node = self.node.non_terminal.match
            edge_style = "solid"
        if not match_node:
            return
        self.graph.add_node(match_node.offset)
        if match_node.is_terminal():
            self.graph.nodes[match_node.offset]["end"] = True
            self.graph.nodes[match_node.offset]["color"] = "blue"
        self.graph.add_edge(self.node.offset, match_node.offset, style=edge_style)
        self.nodes_to_process.add(match_node)

    def decide_and_add_paths(self) -> None:
        non_terminal = self.node.non_terminal
        match_is_terminal = non_terminal.match.is_terminal()
        unmatch_is_terminal = non_terminal.unmatch.is_terminal()
        if not match_is_terminal and not unmatch_is_terminal:
            self.add_path(False)
            self.add_path(True)
        elif not match_is_terminal and unmatch_is_terminal:
            self.add_path(non_terminal.unmatch.terminal.is_allow())
            self.add_path(not non_terminal.unmatch.terminal.is_allow())
        elif match_is_terminal and not unmatch_is_terminal:
            self.add_path(non_terminal.match.terminal.is_allow())
            self.add_path(not non_terminal.match.terminal.is_allow())
        elif match_is_terminal and unmatch_is_terminal:
            self.add_path(True)
            self.add_path(False)

    def build_operation_node_graph(self):
        while self.nodes_to_process:
            self.node = self.nodes_to_process.pop()
            if self.node.is_terminal():
                continue
            self.graph.add_node(self.node.offset)
            self.decide_and_add_paths()
        return self.graph

    def visualize(self):
        pydot_graph = nx.drawing.nx_pydot.to_pydot(self.graph)
        pydot_graph.write_dot("graph.dot")
