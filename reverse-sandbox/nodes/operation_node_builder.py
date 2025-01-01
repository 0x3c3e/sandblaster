import logging
import networkx as nx

logger = logging.getLogger(__name__)


class OperationNodeGraphBuilder:
    def __init__(self, node):
        self.graph = nx.DiGraph()
        self.graph.add_node(node.offset, start=True, color="red")
        self.nodes_to_process = {node}

    def _add_path_to_graph(self, node, reverse: bool = False) -> None:
        if reverse:
            match_node = node.non_terminal.unmatch
            edge_style = "dashed"
        else:
            match_node = node.non_terminal.match
            edge_style = "solid"
        if match_node:
            self.graph.add_node(match_node.offset)
            if match_node.is_terminal():
                self.graph.nodes[match_node.offset]["end"] = True
                self.graph.nodes[match_node.offset]["color"] = "blue"
            self.graph.add_edge(node.offset, match_node.offset, style=edge_style)
            self.nodes_to_process.add(match_node)

    def _decide_and_add_paths(self, current_node) -> None:
        def add_path(reverse=False):
            self._add_path_to_graph(current_node, reverse)

        non_terminal = current_node.non_terminal
        match_is_terminal = non_terminal.match.is_terminal()
        unmatch_is_terminal = non_terminal.unmatch.is_terminal()
        if not match_is_terminal and not unmatch_is_terminal:
            add_path()
            add_path(True)
        elif not match_is_terminal and unmatch_is_terminal:
            add_path(not non_terminal.unmatch.terminal.is_allow())
            add_path(non_terminal.unmatch.terminal.is_allow())
        elif match_is_terminal and not unmatch_is_terminal:
            add_path(non_terminal.match.terminal.is_allow())
            add_path(not non_terminal.match.terminal.is_allow())
        elif match_is_terminal and unmatch_is_terminal:
            add_path(not non_terminal.unmatch.terminal.is_allow())
            add_path(non_terminal.match.terminal.is_allow())

    def _traverse_nodes_to_process(self) -> None:
        while self.nodes_to_process:
            current_node = self.nodes_to_process.pop()
            if current_node.is_terminal():
                continue
            self.graph.add_node(current_node.offset)
            self._decide_and_add_paths(current_node)

    def build_operation_node_graph(self):
        self._traverse_nodes_to_process()
        return self.graph

    def print_digraph(self, nodes):
        print("Nodes:")
        start_nodes = []
        end_nodes = []
        for node_label, data in self.graph.nodes(data=True):
            print(node_label, data)
            if data.get("start"):
                start_nodes.append(node_label)
            elif data.get("end"):
                end_nodes.append(node_label)
        print("\nEdges:")
        for edge in self.graph.edges(data=True):
            print(f"{edge[0]}  ->  {edge[1]}")
        print(start_nodes)
        print(end_nodes)
        if start_nodes and end_nodes:
            for path in nx.all_simple_paths(self.graph, start_nodes[0], end_nodes):
                for step_node in path:
                    print(step_node, nodes.find_operation_node_by_offset(step_node))
                print("NEW")

    def visualize_graph(self):
        pydot_graph = nx.drawing.nx_pydot.to_pydot(self.graph)
        pydot_graph.write_dot("graph.dot")
