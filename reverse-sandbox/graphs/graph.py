import networkx as nx


class ReducedOperation:
    def __init__(self, operation, operands):
        self.operation = operation
        self.operands = operands

    def __str__(self):
        sorted_operands = sorted(str(op) for op in self.operands)
        return f"{self.operation}({', '.join(sorted_operands)})"


class Graph:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def reduce(self):
        while (
            self.merge_chain()
            or self.merge_into_or()
            or self.merge_into_and()
            or self.merge_multiple_inbounds_multiple_outbounds()
            or self.merge_multiple_inbounds_single_outbound()
        ):
            pass

    def find_node_with_multiple_inbounds_same_node_parent(self):
        for node in self.find_nodes_with_multiple_inbounds():
            history = {}
            for parent, _ in self.graph.in_edges(node):
                if (
                    self.graph.in_degree(parent) != 1
                    or self.graph.out_degree(parent) != 1
                ):
                    continue

                grandparent = list(self.graph.in_edges(parent))[0][0]
                history.setdefault(grandparent, set()).add(parent)

            largest_len = 0
            largest_key = None
            for key in history.keys():
                data = history[key]
                current_length = len(data)
                if current_length > largest_len:
                    largest_key = key
                    largest_len = current_length
            if largest_len >= 2:
                yield largest_key, history[largest_key], node

    def merge_into_or(self):
        nodes = next(self.find_node_with_multiple_inbounds_same_node_parent(), None)
        if not nodes:
            return False

        start_node, between_nodes, end_node = nodes
        for between_node in between_nodes:
            self.graph.remove_node(between_node)

        new_node = ReducedOperation("require-any", between_nodes)
        self.graph.add_node(new_node)
        self.graph.add_edge(start_node, new_node)
        self.graph.add_edge(new_node, end_node)
        return True

    def find_node_path_single_chain(self):
        def walk(node):
            path = [node]
            while self.graph.out_degree(node) == 1:
                _, child = list(self.graph.out_edges(node))[0]
                if (
                    self.graph.in_degree(child) == 1
                    and self.graph.out_degree(child) == 1
                ):
                    path.append(child)
                    node = child
                else:
                    break
            return path

        for node in self.graph.nodes():
            if self.graph.out_degree(node) == 1 and self.graph.in_degree(node) == 1:
                path = walk(node)
                if len(path) > 1:
                    yield path

    def find_node_path_single_inbound_single_outbound(self):
        for node in self.graph.nodes():
            if self.graph.out_degree(node) == 1 and self.graph.in_degree(node) >= 1:
                _, child = list(self.graph.out_edges(node))[0]
                if (
                    self.graph.out_degree(child) >= 1
                    and self.graph.in_degree(child) == 1
                ):
                    yield node, child

    def merge_chain(self):
        path = next(self.find_node_path_single_chain(), None)
        if not path:
            return False

        start_nodes = list(self.graph.in_edges(path[0]))
        end_nodes = list(self.graph.out_edges(path[-1]))
        new_node = ReducedOperation("require-all", path)

        self.graph.add_node(new_node)
        for node in path:
            self.graph.remove_node(node)

        for start, _ in start_nodes:
            self.graph.add_edge(start, new_node)
        for _, end in end_nodes:
            self.graph.add_edge(new_node, end)
        return True

    def merge_into_and(self):
        path = next(self.find_node_path_single_inbound_single_outbound(), None)
        if not path:
            return False

        start_nodes = list(self.graph.in_edges(path[0]))
        end_nodes = list(self.graph.out_edges(path[1]))
        new_node = ReducedOperation("require-all", path)

        self.graph.add_node(new_node)
        for node in path:
            self.graph.remove_node(node)

        for start, _ in start_nodes:
            self.graph.add_edge(start, new_node)
        for _, end in end_nodes:
            self.graph.add_edge(new_node, end)
        return True

    def find_nodes_with_multiple_inbounds(self, exclude_end_nodes=False):
        for node in self.graph:
            if exclude_end_nodes and self.graph.out_degree(node) < 1:
                continue
            if self.graph.in_degree(node) > 1:
                yield node

    def find_node_with_multiple_outbounds(self, node):
        for parent, _ in self.graph.in_edges(node):
            if self.graph.out_degree(parent) > 1 and self.graph.in_degree(parent) == 1:
                yield parent

    def find_node_with_single_outbound(self, node):
        for parent, _ in self.graph.in_edges(node):
            if self.graph.out_degree(parent) == 1 and self.graph.in_degree(parent) == 1:
                yield parent

    def merge_multiple_inbounds_multiple_outbounds(self):
        for output_node in self.find_nodes_with_multiple_inbounds(True):
            for input_node in self.find_node_with_multiple_outbounds(output_node):
                if not input_node or not output_node:
                    continue

                self.graph.remove_edge(input_node, output_node)
                new_node = ReducedOperation("require-all", [input_node, output_node])

                self.graph.add_node(new_node)
                for src, _ in self.graph.in_edges(input_node):
                    self.graph.add_edge(src, new_node)
                for _, dst in self.graph.out_edges(output_node):
                    self.graph.add_edge(new_node, dst)

                return True
        return False

    def merge_multiple_inbounds_single_outbound(self):
        for output_node in self.find_nodes_with_multiple_inbounds(True):
            for input_node in self.find_node_with_single_outbound(output_node):
                if not input_node or not output_node:
                    continue

                self.graph.remove_edge(input_node, output_node)
                new_node = ReducedOperation("require-all", [input_node, output_node])

                self.graph.add_node(new_node)
                for src, _ in self.graph.in_edges(input_node):
                    self.graph.add_edge(src, new_node)
                for _, dst in self.graph.out_edges(output_node):
                    self.graph.add_edge(new_node, dst)

                self.graph.remove_node(input_node)
                return True
        return False


def get_subgraph_from_start_to_end(graph, start, end):
    reachable_from_start = nx.descendants(graph, start) | {start}
    reachable_to_end = nx.descendants(graph.reverse(copy=True), end) | {end}
    return graph.subgraph(reachable_from_start & reachable_to_end).copy()


def get_subgraph_to_end(graph, end):
    reachable_to_end = nx.descendants(graph.reverse(copy=True), end) | {end}
    return graph.subgraph(reachable_to_end).copy()


def get_subgraphs(graph):
    for sink in (node for node, degree in graph.out_degree() if degree == 0):
        subgraph = get_subgraph_to_end(graph, sink)
        sources = [node for node, degree in subgraph.in_degree() if degree == 0]
        for source in sources:
            yield get_subgraph_from_start_to_end(subgraph, source, sink)
