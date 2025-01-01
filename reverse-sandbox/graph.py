import networkx as nx



import networkx as nx

def reduce_graph(subgraph):
    previous = subgraph.copy()
    while True:
        subgraph = merge_or_nodes(subgraph)
        linear_chains = find_linear_chains_all(subgraph)
        print(linear_chains)
        merge_chains(subgraph, linear_chains)
        if subgraph.number_of_nodes() == previous.number_of_nodes() and subgraph.number_of_edges() == previous.number_of_edges():
            break
        previous = subgraph.copy()
    return subgraph

def get_subraph_from_start_to_end(sebgraph, start, end):
    reachable_from_A = nx.descendants(sebgraph, start) | {start}  # descendants() excludes the node itself by default

    # 2. Find all nodes that can reach B (i.e., from which B is reachable)
    #    One way is to use the reverse graph and do BFS/DFS from B:
    G_rev = sebgraph.reverse(copy=True)
    can_reach_B = nx.descendants(G_rev, end) | {end}  # or use "ancestors()" with the original G

    # 3. Intersection
    S = reachable_from_A & can_reach_B

    # 4. Induce the subgraph
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
            print(node, a, b)
            if data.get('end'):
                continue
            if G.out_degree(b) == 1 and G.in_degree(b) == 1:
                paths.append([node, b])
    print(paths)
    return paths



def merge_chains(G, chains):
    """
    Merge each chain in 'chains' into a single node labeled "and (n1,n2,...)".

    Steps:
    - For each chain, create a new node with a combined label.
    - Connect incoming edges to the chain start -> new node.
    - Connect outgoing edges from the chain end -> new node.
    - Remove old nodes in the chain.
    """
    flag = False
    for chain in chains:
        if len(chain) < 2:
            continue
        for node in chain:
            if not G.has_node(node):
                flag = True
        if flag:
            continue
        # Build new label
        new_label = "and (" + ", ".join(str(a) for a in chain) + ")"

        # The start and end of this chain
        start_node = chain[0]
        end_node = chain[-1]
        print(start_node, end_node)
        # Add the new merged node
        G.add_node(new_label)

        # Rewire incoming edges of the start node to the new merged node
        for pred in list(G.predecessors(start_node)):
            G.add_edge(pred, new_label)

        # Rewire outgoing edges of the end node to the new merged node
        for succ in list(G.successors(end_node)):
            G.add_edge(new_label, succ)

        # Remove the old nodes from the graph
        for old_node in chain:
            if old_node in G:
                # Before removing, remove edges from old_node to avoid conflicts
                G.remove_node(old_node)

def merge_or_nodes(G: nx.DiGraph) -> nx.DiGraph:
    """
    Merge nodes that share the same predecessor set and successor set
    into a single 'or(...)' node.
    """
    # Step 1: Build signature dictionary
    signature_dict = {}
    for node in list(G.nodes()):
        preds = frozenset(G.predecessors(node))
        succs = frozenset(G.successors(node))
        signature = (preds, succs)
        
        if signature not in signature_dict:
            signature_dict[signature] = []
        signature_dict[signature].append(node)
    
    # We will do merging in a copy so we don’t mutate as we iterate
    H = G.copy()
    
    # Step 2: Merge groups
    for signature, nodes_with_sig in signature_dict.items():
        if len(nodes_with_sig) < 2:
            # Only 1 node with this signature, no merge needed
            continue
        
        preds, succs = signature
        
        # Create the new merged node label
        merged_label = "or (" + ", ".join(str(a) for a in sorted(str(b) for  b in nodes_with_sig)) + ")"
        
        # Add the new node to the graph
        H.add_node(merged_label)
        
        # Wire the new node in (predecessors -> or-node -> successors)
        for p in preds:
            H.add_edge(p, merged_label)
        for s in succs:
            H.add_edge(merged_label, s)
        
        # Remove the old nodes
        for old_node in nodes_with_sig:
            if old_node in H:
                # Before removing, remove all edges from preds and to succs
                if H.has_node(old_node):
                    H.remove_node(old_node)
    
    return H
