import logging
import networkx as nx

logger = logging.getLogger(__name__)


class OperationNodeGraphBuilder:
    def __init__(self):
        self.paths = []
        self.current_path = []

    def ong_add_to_path(self, g, node, nodes_to_process, reverse=False):
        if reverse:
            match_node = node.non_terminal.unmatch
        else:
            match_node = node.non_terminal.match
        if match_node:
            g.add_node(match_node.offset)
            g.add_edge(node.offset, match_node.offset)
            if not match_node.processed:
                nodes_to_process.add((node, match_node))

    def ong_add_to_parent_path(self, g, node, parent_node, nodes_to_process, reverse=False):
        if reverse:
            unmatch_node = node.non_terminal.match
        else:
            unmatch_node = node.non_terminal.unmatch
        if unmatch_node:
            if parent_node:
                g.add_node(unmatch_node.offset)
                g.add_edge(parent_node.offset, unmatch_node.offset)
            if not unmatch_node.processed:
                nodes_to_process.add((parent_node, unmatch_node))

    def _initialize_graph(self, node):
        g = nx.DiGraph()
        g.add_node(node.offset, start=True)
        nodes_to_process = {(None, node)}
        return g, nodes_to_process

    def process_current_node(
        self, g, parent_node, current_node, nodes_to_process, allow_mode
    ):
        def add_to_path(reverse=False):
            self.ong_add_to_path(g, current_node, nodes_to_process, reverse)

        def add_to_parent_path(reverse=False):
            self.ong_add_to_parent_path(g, current_node, parent_node, nodes_to_process, reverse)

        non_terminal = current_node.non_terminal
        match_is_terminal = non_terminal.match.is_terminal()
        unmatch_is_terminal = non_terminal.unmatch.is_terminal()
        print("WTF", parent_node, current_node)
        if not match_is_terminal and not unmatch_is_terminal:
            add_to_path()
            add_to_parent_path()
        elif not match_is_terminal and unmatch_is_terminal:
            if allow_mode == non_terminal.unmatch.terminal.is_allow():
                add_to_path()
            else:
                add_to_parent_path(True)
        elif match_is_terminal and not unmatch_is_terminal:
            if allow_mode == non_terminal.match.terminal.is_allow():
                add_to_path(True)
            else:
                add_to_parent_path()
        elif match_is_terminal and unmatch_is_terminal:
            pass

    def _process_current_node(
        self, g, parent_node, current_node, nodes_to_process, default_node
    ):
        g.add_node(current_node.offset)
        self.process_current_node(
            g,
            parent_node,
            current_node,
            nodes_to_process,
            default_node.terminal.is_allow(),
        )

    def _process_all_nodes(self, g, nodes_to_process, default_node):
        while nodes_to_process:
            parent_node, current_node = nodes_to_process.pop()
            if current_node.processed:
                continue
            if parent_node is None:
                parent_node = current_node
            self._process_current_node(
                g, parent_node, current_node, nodes_to_process, default_node
            )
            current_node.processed = True

    def build_operation_node_graph(self, node, default_node):
        if node.is_terminal():
            return None

        g, nodes_to_process = self._initialize_graph(node)
        self._process_all_nodes(g, nodes_to_process, default_node)
        return g

    def get_operation_node_graph_paths(self, g, start_node):
        return list(nx.all_simple_paths(g, source=start_node, target=None))

    def remove_node_in_operation_node_graph(self, g, node_to_remove):
        g.remove_node(node_to_remove)
        return g

    def print_digraph(self, g):
        print("Nodes:")
        for node, data in g.nodes(data=True):
            print(f"{node}: {data}")
        print("\nEdges:")
        for edge in g.edges(data=True):
            print(edge[0], " -> ", edge[1])

    def print_recursive_edges(self, g, node, deep, outfile, visited=None):
        # Print the current node
        # print(deep)
        # if deep > 5:
        #     return
        for line in str(node).splitlines():
            outfile.write(f'{"  " * deep}{line}\n')
        
        # Iterate through edges from the current node
        for neighbor in g.successors(node):  # Get neighbors (successors) in the DiGraph
            # Recursive call for the target node
            self.print_recursive_edges(g, neighbor, deep + 1, outfile, visited)


    def visualize_graph(self, g):
        p=nx.drawing.nx_pydot.to_pydot(g)
        p.write_dot('graph.dot')
