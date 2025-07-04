import networkx as nx
import z3


def make_tactic_with_timeout(timeout_ms):
    return z3.Then(
        z3.With("cofactor-term-ite", timeout=timeout_ms),
        z3.With("aig", timeout=timeout_ms),
        z3.With("qe", timeout=timeout_ms),
        z3.With("ctx-simplify", timeout=timeout_ms),
    )


def make_fallback_tactic():
    return z3.Then(
        z3.Tactic("cofactor-term-ite"),
        z3.Tactic("aig"),
        z3.Tactic("qe"),
        z3.Tactic("simplify"),
    )


def ite_expr_to_nnf(expr, timeout_ms=600):
    """
    Applies NNF transformation with ctx-simplify and timeout fallback.
    """
    goal = z3.Goal()
    goal.add(expr)

    try:
        tactic = make_tactic_with_timeout(timeout_ms)
        result = tactic(goal)
        return result[0].as_expr()
    except z3.Z3Exception:
        fallback_tactic = make_fallback_tactic()
        result = fallback_tactic(goal)
        return result[0].as_expr()


def build_ite_expr(graph, start_node):
    """
    Builds an ITE expression from a control-flow graph rooted at start_node.
    """
    node_to_expr = {}

    for node in reversed(list(nx.topological_sort(graph))):
        if graph.out_degree(node) == 0:
            node_to_expr[node] = z3.BoolVal(True)
            continue

        cond_id = graph.nodes[node].get("id")
        condition = z3.Bool(str(cond_id))

        true_expr = None
        false_expr = None

        for _, target, data in graph.out_edges(node, data=True):
            result = data.get("result")
            target_expr = node_to_expr[target]

            if result == 1:
                true_expr = target_expr
            elif result == 0:
                false_expr = target_expr

        true_expr = true_expr if true_expr is not None else z3.BoolVal(False)
        false_expr = false_expr if false_expr is not None else z3.BoolVal(False)

        ite_expr = z3.If(condition, true_expr, false_expr)
        node_to_expr[node] = ite_expr_to_nnf(ite_expr)

    return node_to_expr[start_node]
