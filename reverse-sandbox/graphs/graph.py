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


def sbpl_to_string(data, indent=0, indent_size=4):
    current_indent = " " * (indent * indent_size)

    if isinstance(data, dict):
        if len(data) != 1:
            raise ValueError(f"Expected a dict with exactly one key, got: {data}")
        operator = next(iter(data))
        value = data[operator]
        sbpl_str = f"{current_indent}({operator}\n"
        sbpl_str += sbpl_list_to_string(value, indent + 1, indent_size)
        sbpl_str += f"{current_indent})\n"
        return sbpl_str

    elif isinstance(data, list):
        return sbpl_list_to_string(data, indent, indent_size)

    elif isinstance(data, str):
        lines = data.splitlines()
        if len(lines) == 1:
            return f"{current_indent}{lines[0]}\n"

        sbpl_str = ""
        sbpl_str += f"{current_indent}{lines[0]}\n"
        for line in lines[1:-1]:
            sbpl_str += f"{current_indent}{' ' * indent_size}{line}\n"
        sbpl_str += f"{current_indent}{lines[-1]}\n"
        return sbpl_str

    else:
        raise TypeError(f"Unsupported data type: {type(data)} => {data}")


def sbpl_list_to_string(data_list, indent=0, indent_size=4):
    sbpl_str = ""
    for item in data_list:
        sbpl_str += sbpl_to_string(item, indent, indent_size)
    return sbpl_str
