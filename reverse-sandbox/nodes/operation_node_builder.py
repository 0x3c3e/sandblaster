import logging
import networkx as nx

logger = logging.getLogger(__name__)

import networkx as nx

def find_linear_chains_all(G):
    """
    Find all maximal linear chains in a directed graph G.

    A 'linear chain' is any path of length >= 2 where every
    *internal* node has (in_degree=1, out_degree=1).

    Special condition: any node with attribute `end=True` is treated as a 
    boundary node (the chain should NOT include it).

    Approach:
      (1) Identify 'boundary' nodes:
          - any node whose in_degree != 1 or out_degree != 1
          - OR any node that has the attribute `end=True`
      (2) For each boundary node b with out_degree=1, follow the chain 
          forward as long as each successor is a valid chain node 
          (in_degree=1, out_degree=1, end!=True).
      (3) Record each chain (>=2 nodes), mark them visited.
      (4) SECOND PASS: For any unvisited node that has out_degree=1, 
          do the same chain-following process (covers fully-linear subgraphs
          with no boundary in them).
    """

    visited = set()
    chains = []

    # 1) Identify boundary nodes
    boundary_nodes = {
        n for n in G.nodes()
        if G.in_degree(n) != 1
        or G.out_degree(n) != 1
        or G.nodes[n].get("end", False) is True  # treat end=True as boundary
    }

    def follow_chain(start):
        """
        Follow a chain forward from `start`.
        
        - The chain continues only if the successor has (in_degree=1, out_degree=1)
          and does NOT have end=True.
        - If we hit a boundary node, or a node with end=True, or no unique successor,
          we stop BEFORE that node if it has end=True, or potentially include it 
          if it's a boundary node with in_degree=1/out_degree=1 (but NOT end=True).
        """
        current_chain = [start]
        visited.add(start)

        successors = list(G.successors(start))
        while len(successors) == 1:
            nxt = successors[0]

            if nxt in visited:
                # Already part of another chain
                break

            # If this node is explicitly end=True, STOP before it:
            if G.nodes[nxt].get("end", False) is True:
                # do NOT include it in the chain
                break

            # Check if it's an "internal" chain node (in_degree=1, out_degree=1)
            # AND not end=True
            if G.in_degree(nxt) == 1 and G.out_degree(nxt) == 1:
                current_chain.append(nxt)
                visited.add(nxt)
                successors = list(G.successors(nxt))
            else:
                # If it's a boundary node but in_degree(nxt)=1,
                # we can include it as the last chain node UNLESS it has end=True.
                if G.in_degree(nxt) == 1:
                    current_chain.append(nxt)
                    visited.add(nxt)
                break

        return current_chain

    # 2) First pass: from each boundary node that has out_degree=1
    for b in boundary_nodes:
        if b not in visited and G.out_degree(b) == 1:
            # If b itself is end=True, we skip it for chain start
            if G.nodes[b].get("end", False) is True:
                continue
            chain_nodes = follow_chain(b)
            if len(chain_nodes) >= 2:
                chains.append(chain_nodes)

    # 3) Second pass: any unvisited node with out_degree=1 could be a chain start
    for node in G.nodes():
        if node not in visited and G.out_degree(node) == 1:
            # If node is end=True, skip
            if G.nodes[node].get("end", False) is True:
                continue
            chain_nodes = follow_chain(node)
            if len(chain_nodes) >= 2:
                chains.append(chain_nodes)

    return chains
def merge_chains(G, chains):
    """
    Merge each chain in 'chains' into a single node labeled "and (n1,n2,...)".

    Steps:
    - For each chain, create a new node with a combined label.
    - Connect incoming edges to the chain start -> new node.
    - Connect outgoing edges from the chain end -> new node.
    - Remove old nodes in the chain.
    """
    for chain in chains:
        if len(chain) < 2:
            continue

        # Build new label
        new_label = "and (" + ", ".join(str(a) for a in chain) + ")"

        # The start and end of this chain
        start_node = chain[0]
        end_node = chain[-1]

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
        start_nodes = [node for node, deg in graph.in_degree() if deg == 0]
        end_nodes = []
        for node_label, data in graph.nodes(data=True):
            if data.get("end"):
                end_nodes.append(node_label)
        for path in nx.all_simple_paths(graph, start_nodes[0], end_nodes):
            print("NEW PATH")
            for step_node in path:
                print(step_node)

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
        previous = subgraph.copy()
        while True:
            subgraph = merge_or_nodes(subgraph)
            linear_chains = find_linear_chains_all(subgraph)
            merge_chains(subgraph, linear_chains)
            print(subgraph, previous)
            if subgraph.number_of_nodes() == previous.number_of_nodes() and subgraph.number_of_edges() == previous.number_of_edges():
                break
            previous = subgraph.copy()
            print("HERE")
        return subgraph