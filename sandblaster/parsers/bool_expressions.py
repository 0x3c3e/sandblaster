import pprint

import networkx as nx
import z3

from sandblaster.parsers.graph import GraphParser
from sandblaster.parsers.profile import SandboxPayload


def ite_expr_to_nnf(ite_expr):
    g = z3.Goal()
    g.add(ite_expr)
    cnf_tactic = z3.Then("simplify", "nnf")
    subgoals = cnf_tactic(g)
    nnf_expr = subgoals[0].as_expr()

    return nnf_expr


def build_ite_expr(graph, start_node):
    node_to_expr = {}
    for node in reversed(list(nx.topological_sort(graph))):
        if graph.out_degree(node) == 0:
            node_to_expr[node] = z3.BoolVal(True)
            continue

        cond = z3.Bool(str(node))
        true_expr = z3.BoolVal(False)
        false_expr = z3.BoolVal(False)

        for _, tgt, data in graph.out_edges(node, data=True):
            if data.get("result") == 1:
                true_expr = node_to_expr[tgt]
            elif data.get("result") == 0:
                false_expr = node_to_expr[tgt]

        node_to_expr[node] = z3.If(cond, true_expr, false_expr)

    return node_to_expr[start_node]


def get_subgraph(graph, sink):
    reachable_to_end = nx.descendants(graph.reverse(copy=True), sink) | {sink}
    return graph.subgraph(reachable_to_end).copy()


def get_nnf_forms(node):
    result = []
    graph = GraphParser(node).parse()
    for sink in [n for n in nx.topological_sort(graph) if graph.out_degree(n) == 0]:
        subgraph = get_subgraph(graph, sink)
        for start in [n for n, deg in subgraph.in_degree() if deg == 0]:
            ite = build_ite_expr(subgraph, start)
            nnf_expr = ite_expr_to_nnf(ite)
            result.append((sink, nnf_expr))
        graph.remove_nodes_from(subgraph.nodes())
    return result


def process_profile(payload: SandboxPayload) -> None:
    for idx in payload.ops_to_reverse:
        print(payload.sb_ops[idx])
        offset = payload.op_table[idx]

        node = payload.operation_nodes.find_operation_node_by_offset(offset)
        if not node:
            continue
        nnf_forms = get_nnf_forms(node)
        pprint.pprint(nnf_forms)
