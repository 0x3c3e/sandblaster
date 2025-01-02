import networkx as nx


class ReducedOperation:
    def __init__(self, operation, operands):
        self.operation = operation
        self.operands = operands

    def __str__(self):
        return (
            self.operation
            + "("
            + ", ".join(str(a) for a in sorted(str(b) for b in self.operands))
            + ")"
        )


class Graph:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def reduce(self):
        flag = True
        while flag:
            flag = (
                self.merge_into_or()
                or self.merge_into_and()
                or self.collapse_multiple_inbounds()
            )
            if not flag:
                flag = self.merge_multiple_inbounds_single_outbound()

    def find_node_with_multiple_inbounds_same_node_parent(self):
        for node in self.find_node_with_multiple_inbounds():
            history = {}
            for parent, child in self.graph.in_edges(node):
                if (
                    self.graph.in_degree(parent) != 1
                    or self.graph.out_degree(parent) != 1
                ):
                    continue
                current = list(self.graph.in_edges(parent))[0][0]
                if current not in history:
                    history[current] = set()
                    history[current].add(parent)
                else:
                    history[current].add(parent)
                    yield (current, history[current], node)

    def merge_into_or(self):
        nodes = next(self.find_node_with_multiple_inbounds_same_node_parent(), None)
        if not nodes:
            return False
        start_node = nodes[0]
        end_node = nodes[2]
        between_nodes = nodes[1]
        for between_node in between_nodes:
            self.graph.remove_edge(start_node, between_node)
            self.graph.remove_edge(between_node, end_node)
            self.graph.remove_node(between_node)
        new_node_name = ReducedOperation("require-any", between_nodes)
        self.graph.add_node(new_node_name)
        self.graph.add_edge(start_node, new_node_name)
        self.graph.add_edge(new_node_name, end_node)
        return True

    def find_node_path_single_inbound_single_outbound(self):
        for node in self.graph.nodes():
            if self.graph.out_degree(node) == 1 and self.graph.in_degree(node) >= 1:
                a, b = list(self.graph.out_edges(node))[0]
                if self.graph.out_degree(b) >= 1 and self.graph.in_degree(b) == 1:
                    yield (node, b)

    def merge_into_and(self):
        path = next(self.find_node_path_single_inbound_single_outbound(), None)
        if not path:
            return False
        start_nodes = list(self.graph.in_edges(path[0]))
        end_nodes = list(self.graph.out_edges(path[1]))
        new_node_name = ReducedOperation("require-all", path)
        self.graph.add_node(new_node_name)
        for node in path:
            self.graph.remove_node(node)
        for node in start_nodes:
            self.graph.add_edge(node[0], new_node_name)
        for node in end_nodes:
            self.graph.add_edge(new_node_name, node[1])
        return True

    def find_node_with_multiple_inbounds(self, not_end=False):
        for node in self.graph:
            if not_end and self.graph.out_degree(node) < 1:
                continue
            if self.graph.in_degree(node) <= 1:
                continue
            yield node

    def find_node_with_multiple_outbounds(self, node):
        for input_node, _ in self.graph.in_edges(node):
            if (
                self.graph.out_degree(input_node) > 1
                and self.graph.in_degree(input_node) == 1
            ):
                yield input_node

    def find_node_with_single_outbounds(self, node):
        for input_node, _ in self.graph.in_edges(node):
            if (
                self.graph.out_degree(input_node) == 1
                and self.graph.in_degree(input_node) == 1
            ):
                yield input_node

    def collapse_multiple_inbounds(self):
        # make sure that node isn't an end, with no inbound nodes
        # find a node with multiple inbound nodes
        # find a node with multiple outbound nodes
        # if it's a match, then remove that edge between these two nodes
        for output_node in self.find_node_with_multiple_inbounds(True):
            for input_node in self.find_node_with_multiple_outbounds(output_node):
                if not input_node or not output_node:
                    continue
                self.graph.remove_edge(input_node, output_node)
                new_node_name = ReducedOperation(
                    "require-all", [input_node, output_node]
                )
                self.graph.add_node(new_node_name)
                for edge in self.graph.in_edges(input_node):
                    self.graph.add_edge(edge[0], new_node_name)
                for edge in self.graph.out_edges(output_node):
                    self.graph.add_edge(new_node_name, edge[1])
                return True
        return False

    def merge_multiple_inbounds_single_outbound(self):
        for output_node in self.find_node_with_multiple_inbounds(True):
            for input_node in self.find_node_with_single_outbounds(output_node):
                if not input_node or not output_node:
                    continue
                self.graph.remove_edge(input_node, output_node)
                new_node_name = ReducedOperation(
                    "require-all", [input_node, output_node]
                )
                self.graph.add_node(new_node_name)
                for edge in self.graph.in_edges(input_node):
                    self.graph.add_edge(edge[0], new_node_name)
                for edge in self.graph.out_edges(output_node):
                    self.graph.add_edge(new_node_name, edge[1])
                self.graph.remove_node(input_node)
                return True
        return False


if __name__ == "__main__":
    graph = nx.DiGraph()
    graph.add_node("A")
    graph.add_node("B")
    graph.add_node("C")
    graph.add_node("D")
    graph.add_node("E")

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "D")
    # graph.add_edge("C", "D")
    # graph.add_edge("D", "E")

    for node in graph.nodes():
        print(node)
    for a, b in graph.edges():
        print(f"{a} -> {b}")

    reduced = Graph(graph)
    reduced.reduce()
    for node in reduced.graph.nodes():
        print(node)
    for a, b in reduced.graph.edges():
        print(f"{a} -> {b}")
