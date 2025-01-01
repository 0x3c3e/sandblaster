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

    def print(self, graph, nodes):
        for node, data in graph.nodes(data=True):
            print(node, nodes.find_operation_node_by_offset(node))

    def visualize(self):
        pydot_graph = nx.drawing.nx_pydot.to_pydot(self.graph)
        pydot_graph.write_dot("graph.dot")

    def build_subgraph_with_edge_style(self, style_value: str) -> nx.DiGraph:
        for node, data in self.graph.nodes(data=True):
            if data.get("start"):
                start_node = node
                break

        subgraph = nx.DiGraph()
        subgraph.add_nodes_from(self.graph.nodes(data=True))

        for u, v, edge_data in self.graph.edges(data=True):
            if edge_data.get("style") == style_value:
                subgraph.add_edge(u, v, **edge_data)
        source_nodes = [node for node, deg in subgraph.in_degree() if deg == 0]
        for node in source_nodes:
            shortest_path = list(reversed(nx.shortest_path(self.graph, start_node, node)))
            for i in range(len(shortest_path) - 1):
                edge_data = self.graph.get_edge_data(shortest_path[i + 1], shortest_path[i])
                if edge_data["style"] == style_value and subgraph.has_node(shortest_path[i + 1]):
                    subgraph.add_edge(shortest_path[i + 1], node)
                    break

        return subgraph