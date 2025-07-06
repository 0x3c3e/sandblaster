import networkx as nx


def compute_graph(graph, sink, other_sink, visited):
    guards = {pred for pred in graph.predecessors(other_sink)}

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
    return (edge_score) * 1.1 + idx


def evaluate_candidate(graph, sink, s, visited, idx):
    subgraph, updated_visited = compute_graph(graph, sink, s, visited)
    weight = compute_weight(subgraph, idx)
    return (weight, sink, subgraph, updated_visited)


def backward_partition(graph, payload):
    def is_sink(node):
        return (
            graph.out_degree(node) == 0
            and payload.operation_nodes.find_operation_node_by_offset(node).type == 0
        )

    sinks = [n for n in nx.topological_sort(graph) if is_sink(n)]
    ss = sinks.copy()
    visited = set()
    partitions = {}
    total = len(sinks)
    i = 0
    while sinks:
        print(f"{i}/{total}")
        i += 1
        candidates = []
        for idx, sink in enumerate(sinks):
            for s in [s for s in ss if s != sink]:
                candidates.append(
                    evaluate_candidate(graph, sink, s, visited.copy(), idx)
                )
        if not candidates:
            candidates.append((0, sink, graph, []))
        _, chosen_sink, chosen_subgraph, visited = min(candidates, key=lambda x: x[0])
        partitions[chosen_sink] = chosen_subgraph
        sinks.remove(chosen_sink)

    return partitions
