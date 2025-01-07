import networkx as nx
import sympy
from sympy.logic.boolalg import And, Or, Not, simplify_logic


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
            yield sink, get_subgraph_from_start_to_end(subgraph, source, sink)


def get_booleans(graph):
    out = None
    memos = {}
    for node in nx.topological_sort(graph):
        for a, b, data in graph.out_edges(node, data=True):
            a_val = memos.get(a, None)
            if a_val is not None:
                a = a_val
            else:
                a = sympy.Symbol(str(a))

            if data["style"] == "solid":
                if graph.out_degree(b) != 0:
                    expr = simplify_logic(And(a, sympy.Symbol(str(b))), form="dnf")
                else:
                    expr = a
            else:
                if graph.out_degree(b) != 0:
                    expr = simplify_logic(And(Not(a), sympy.Symbol(str(b))), form="dnf")
                else:
                    expr = Not(a)

            existing_b = memos.get(b, None)
            if graph.out_degree(b) != 0:
                if existing_b is None:
                    memos[b] = expr
                else:
                    memos[b] = simplify_logic(Or(existing_b, expr), form="dnf")
            else:
                if out is None:
                    out = expr
                else:
                    out = simplify_logic(Or(out, expr), form="dnf")
    return out


def sympy_expr_to_sbpl(expr, operation_nodes):
    if expr.is_Symbol:
        return str(operation_nodes.find_operation_node_by_offset(int(str(expr))))

    if isinstance(expr, Not):
        return {"require-not": [sympy_expr_to_sbpl(expr.args[0], operation_nodes)]}

    if isinstance(expr, And):
        return {
            "require-all": [
                sympy_expr_to_sbpl(arg, operation_nodes) for arg in expr.args
            ]
        }

    if isinstance(expr, Or):
        return {
            "require-any": [
                sympy_expr_to_sbpl(arg, operation_nodes) for arg in expr.args
            ]
        }

    raise ValueError(f"Unsupported expression type: {expr}")
