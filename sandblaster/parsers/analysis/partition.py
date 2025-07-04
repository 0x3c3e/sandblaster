import networkx as nx


def compute_graph(graph, sink, all_sinks, visited):
    guards = {pred for s in all_sinks if s != sink for pred in graph.predecessors(s)}

    subgraph_nodes = set()
    stack = [sink]

    while stack:
        node = stack.pop()
        if node in visited:
            continue

        visited.add(node)
        subgraph_nodes.add(node)

        if node in guards:
            continue

        stack.extend(pred for pred in graph.predecessors(node) if pred not in visited)

    return graph.subgraph(subgraph_nodes), visited


def compute_weight(subgraph, idx):
    edge_score = sum(1 for _, _, d in subgraph.edges(data=True) if d.get("result") == 0)
    return edge_score * 1.1 + idx


def backward_partition(graph, payload):
    def is_sink(node):
        return (
            graph.out_degree(node) == 0
            and payload.operation_nodes.find_operation_node_by_offset(node).type == 0
        )

    sinks = [n for n in nx.topological_sort(graph) if is_sink(n)]
    visited = set()
    partitions = {}

    while sinks:
        candidates = []
        for idx, sink in enumerate(sinks):
            subgraph, updated_visited = compute_graph(
                graph, sink, sinks, visited.copy()
            )
            weight = compute_weight(subgraph, idx)
            candidates.append((weight, sink, subgraph, updated_visited))

        _, chosen_sink, chosen_subgraph, visited = min(candidates)
        partitions[chosen_sink] = chosen_subgraph
        sinks.remove(chosen_sink)

    return partitions
