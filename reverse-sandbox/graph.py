import networkx as nx


def reduce_graph(subgraph):
    previous = subgraph.copy()
    while True:
        subgraph = merge_or_nodes(subgraph)
        linear_chains = find_linear_chains_all(subgraph)
        merge_chains(subgraph, linear_chains)
        if (
            subgraph.number_of_nodes() == previous.number_of_nodes()
            and subgraph.number_of_edges() == previous.number_of_edges()
        ):
            break
        previous = subgraph.copy()
    return subgraph


def get_subraph_from_start_to_end(sebgraph, start, end):
    reachable_from_A = nx.descendants(sebgraph, start) | {start}
    G_rev = sebgraph.reverse(copy=True)
    can_reach_B = nx.descendants(G_rev, end) | {end}
    S = reachable_from_A & can_reach_B
    return sebgraph.subgraph(S).copy()


def get_subraph_to_end(subgraph, end):
    G_rev = subgraph.reverse(copy=True)
    reachable_from_A_in_G_rev = nx.descendants(G_rev, end) | {end}
    subgraph_nodes = list(reachable_from_A_in_G_rev)
    return subgraph.subgraph(subgraph_nodes).copy()


def get_subgraphs(graph):
    for node, data in graph.nodes(data=True):
        if data.get("end"):
            g = get_subraph_to_end(graph, node)
            source_nodes = [node for node, deg in g.in_degree() if deg == 0]
            for source in source_nodes:
                yield get_subraph_from_start_to_end(g, source, node)


def find_linear_chains_all(G):
    paths = []
    for node, data in G.nodes(data=True):
        if G.out_degree(node) == 1 and G.in_degree(node):
            a, b, data = list(G.out_edges(node, data=True))[0]
            if data.get("end"):
                continue
            if G.out_degree(b) == 1 and G.in_degree(b) == 1:
                paths.append([node, b])
    return paths


def merge_chains(G, chains):
    for chain in chains:
        flag = False
        if len(chain) < 2:
            continue
        for node in chain:
            if not G.has_node(node):
                flag = True
        if flag:
            continue
        new_label = ReducedOperation("require-all", chain)
        start_node = chain[0]
        end_node = chain[-1]
        G.add_node(new_label)
        for pred in list(G.predecessors(start_node)):
            G.add_edge(pred, new_label)
        for succ in list(G.successors(end_node)):
            G.add_edge(new_label, succ)
        for old_node in chain:
            if old_node in G:
                G.remove_node(old_node)


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


def merge_or_nodes(G: nx.DiGraph) -> nx.DiGraph:
    signature_dict = {}
    for node in list(G.nodes()):
        preds = frozenset(G.predecessors(node))
        succs = frozenset(G.successors(node))
        signature = (preds, succs)
        if signature not in signature_dict:
            signature_dict[signature] = []
        signature_dict[signature].append(node)

    H = G.copy()

    for signature, nodes_with_sig in signature_dict.items():
        if len(nodes_with_sig) < 2:
            continue
        preds, succs = signature
        merged_label = ReducedOperation("require-any", nodes_with_sig)
        H.add_node(merged_label)
        for p in preds:
            H.add_edge(p, merged_label)
        for s in succs:
            H.add_edge(merged_label, s)
        for old_node in nodes_with_sig:
            if old_node in H:
                if H.has_node(old_node):
                    H.remove_node(old_node)

    return H
