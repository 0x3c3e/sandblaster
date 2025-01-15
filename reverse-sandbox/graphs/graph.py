import networkx as nx

from sympy.logic.boolalg import (
    And,
    Or,
    Not,
    simplify_logic,
    BooleanTrue,
    BooleanFalse,
    ITE,
    Boolean,
    to_nnf,
    to_dnf,
    to_cnf,
)
from sympy import Symbol, true, false


def get_subgraph_from_start_to_end(graph, start, end):
    reachable_from_start = nx.descendants(graph, start) | {start}
    reachable_to_end = nx.descendants(graph.reverse(copy=True), end) | {end}
    return graph.subgraph(reachable_from_start & reachable_to_end).copy()


def get_subgraph_to_end(graph, end):
    reachable_to_end = nx.descendants(graph.reverse(copy=True), end) | {end}
    return graph.subgraph(reachable_to_end).copy()


def get_subgraphs(graph, reverse=False):
    g_copy = graph.copy()

    sinks = [node for node in nx.topological_sort(graph) if graph.out_degree(node) == 0]
    for sink in sinks:
        subgraph = get_subgraph_to_end(g_copy, sink)

        yield sink, subgraph


import networkx as nx
from sympy import Symbol, ITE, true, false
from sympy.logic.boolalg import Boolean

import z3


from sympy.logic.boolalg import to_dnf
from sympy.parsing.sympy_parser import parse_expr


def z3_expr_to_sympy_str(z3_expr):
    """
    A naive way to get a string from a Z3 expression.
    For complex expressions, you might need a more robust translator.
    """
    return str(z3_expr)


def sympy_dnf(expr_str):
    """
    Convert a string-based expression into Sympy, then get DNF.
    """
    sympy_expr = parse_expr(expr_str)
    return simplify_logic(sympy_expr, form="dnf")


def build_ite_iterative_z3(G, start_node):
    """
    Iteratively build a Z3 If-expression from a networkx DiGraph G,
    starting at 'start_node', without using recursion.

    Assumptions:
      - The graph is a DAG (no cycles).
      - 'start_node' is the unique entry.
      - Each internal node has up to two children with edges labeled:
          edge.data['result'] == 1 -> True branch
          edge.data['result'] == 0 -> False branch
      - A leaf node has out_degree == 0. We'll treat that as z3.BoolVal(True) here,
        but you can change it if you want a different leaf value.
    """

    # Topologically sort the graph (parents before children).
    topo_order = list(nx.topological_sort(G))

    # We'll build expressions bottom-up.
    node_to_expr = {}

    # Traverse in reverse topological order so children get processed first.
    for node in reversed(topo_order):

        # If out_degree=0, it's a leaf. Store True (or your desired leaf).
        if G.out_degree(node) == 0:
            node_to_expr[node] = z3.BoolVal(True)
            continue

        # Interpret the node's label as a Z3 Boolean variable.
        label_str = f"{G.nodes[node].get('label')}"
        condition = z3.Bool(label_str)

        # Identify the child for result=1 (true branch) and result=0 (false branch).
        true_succ = None
        false_succ = None
        for _, tgt, data in G.out_edges(node, data=True):
            if data.get("result") == 1:
                true_succ = tgt
            elif data.get("result") == 0:
                false_succ = tgt

        # Handle missing true/false successors if needed.
        true_succ_expr = (
            node_to_expr[true_succ] if true_succ is not None else z3.BoolVal(False)
        )
        false_succ_expr = (
            node_to_expr[false_succ] if false_succ is not None else z3.BoolVal(False)
        )

        # Combine them into a Z3 If-expression.
        node_to_expr[node] = z3.If(condition, true_succ_expr, false_succ_expr)

    # Finally, return the expression for 'start_node' as the top-level ITE.
    return ite_expr_to_cnf_z3(node_to_expr[start_node])


import z3
import sympy
from sympy import Symbol, And, Or, Not, Implies, Xor, Eq
from sympy.logic.boolalg import ITE

import z3
from pyeda.boolalg.expr import exprvar, NotOp, AndOp, OrOp, Variable, Complement


def z3_to_pyeda(z3_expr, varcache=None):
    """
    Convert a boolean-only Z3 expression to a PyEDA expr.
    varcache: dictionary to map var names -> pyeda exprvar objects
    """
    if varcache is None:
        varcache = {}

    # Check if it’s a BoolVal
    if z3_expr.eq(z3.BoolVal(True)):
        return AndOp()  # empty AND => True in PyEDA
    if z3_expr.eq(z3.BoolVal(False)):
        return OrOp()  # empty OR => False in PyEDA

    # If it's a variable
    if (z3_expr.decl().kind() == z3.Z3_OP_UNINTERPRETED) and (z3_expr.num_args() == 0):
        var_name = str(z3_expr)
        if var_name not in varcache:
            varcache[var_name] = exprvar(var_name)
        return varcache[var_name]

    # Otherwise dispatch on operator
    op = z3_expr.decl().kind()
    kids = z3_expr.children()
    if op == z3.Z3_OP_NOT:
        return ~z3_to_pyeda(kids[0], varcache)
    elif op == z3.Z3_OP_AND:
        pykids = [z3_to_pyeda(k, varcache) for k in kids]
        # Combine with operator overload: reduce(lambda a,b: a & b, pykids)
        out = pykids[0]
        for c in pykids[1:]:
            out = out & c
        return out
    elif op == z3.Z3_OP_OR:
        pykids = [z3_to_pyeda(k, varcache) for k in kids]
        out = pykids[0]
        for c in pykids[1:]:
            out = out | c
        return out
    # etc., handle Implies, Xor, ITE, etc. if needed

    raise NotImplementedError(f"Unsupported op kind: {op}")


# Then you can do:
# py_expr = z3_to_pyeda(z3_expr)
# py_expr_sop = py_expr.to_sop()  # sum-of-products
# minimized = espresso_exprs(py_expr_sop)[0]
# print("Minimized:", minimized)


def ite_expr_to_cnf_z3(ite_expr):
    """
    Convert a Z3 expression (e.g. containing If-Then-Else) to CNF using Tseitin encoding.
    Returns a new Z3 expression in CNF form.
    """
    # Create a fresh goal and add the expression to it.
    g = z3.Goal()
    g.add(ite_expr)

    # Use a tactic pipeline: simplify, then convert to CNF via tseitin encoding.
    # 'Then' combines multiple tactics in sequence.
    cnf_tactic = z3.Then("simplify", "nnf")

    # Apply the tactic to the goal. This can produce multiple subgoals (disjunctive cases),
    # but often there's just one.
    subgoals = cnf_tactic(g)

    # subgoals is a list of (possibly multiple) goals. Each goal can have multiple clauses.
    # Usually, we just take the first subgoal.
    # The `.as_expr()` method gives us a Z3 expression representing the conjunction of all its clauses.
    cnf_expr = subgoals[0].as_expr()

    return cnf_expr


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
    if isinstance(expr, BooleanTrue):
        return "true"
    if isinstance(expr, BooleanFalse):
        return "false"
    raise ValueError(f"Unsupported expression type: {expr}")


from pyeda.boolalg.expr import Expression


def pyeda_expr_to_sbpl(expr: Expression, operation_nodes):
    """
    Convert a PyEDA boolean expression into SBPL-like JSON,
    ensuring we don't call is_lit() on compound expressions.
    """

    # 1) True / False
    if expr.is_one():
        return "true"
    if expr.is_zero():
        return "false"

    # 2) Or / And
    if isinstance(expr, OrOp):
        return {
            "require-any": [
                pyeda_expr_to_sbpl(subexpr, operation_nodes) for subexpr in expr.xs
            ]
        }

    if isinstance(expr, AndOp):
        return {
            "require-all": [
                pyeda_expr_to_sbpl(subexpr, operation_nodes) for subexpr in expr.xs
            ]
        }

    # 3) Complement (e.g. ~(x & y)) vs. a negated literal (~x)
    #    If it's a single literal, PyEDA might say expr.is_neg().
    #    But if it's a complement of a bigger expression, expr.is_complement() is True.
    if isinstance(expr, Complement):
        # If that uncomplemented subexpr is a literal, we'd handle it as ~x
        # Otherwise it's ~(some compound).
        return {"require-not": [pyeda_expr_to_sbpl(expr.__invert__(), operation_nodes)]}

    # 4) Literal: x or ~x
    #    For a literal, we can see if it's negated or not.
    if isinstance(expr, Variable):
        if expr.is_zero():
            # e.g. ~x
            var = expr.unnegate()  # => x
            offset = int(str(var))  # parse variable name to int
            return {
                "require-not": [
                    str(operation_nodes.find_operation_node_by_offset(offset))
                ]
            }
        else:
            # e.g. x
            offset = int(str(expr))
            return str(operation_nodes.find_operation_node_by_offset(offset))

    # 5) If none of the above matched, it's an unsupported form
    raise ValueError(f"Unsupported expression structure: {expr}")


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


def find_merge_candidates_for_not_and(G):
    """
    Find pairs (u, v) that should be merged based on an OR-like rule:
      - There's a 'dashed' edge (u -> v) => data["result"] == False
      - B (=v) has exactly one incoming edge
      - u and v share at least one successor x where
        both (u->x) and (v->x) are 'solid' => data["result"] == True
    """
    return {
        (u, v)
        for u, v, data in G.edges(data=True)
        if (
            not data["result"]  # 'dashed' edge (u->v)
            and G.in_degree(v) == 1  # B must have exactly one incoming edge
            and any(
                G[u][x]["result"] and not G[v][x]["result"]
                for x in set(G.successors(u)) & set(G.successors(v))
            )
        )
    }


def find_merge_candidates_for_not_or(G):
    """
    Find pairs (u, v) that should be merged based on a NOT-OR rule:
      - There's a 'solid' edge (u -> v) => data["result"] == True
      - B (=v) has exactly one incoming edge
      - u and v share at least one successor x where:
          (u->x) is 'dashed' => data["result"] == False
          (v->x) is 'solid'  => data["result"] == True
    """
    return {
        (u, v)
        for u, v, data in G.edges(data=True)
        if (
            data["result"]  # 'solid' edge (u->v)
            and G.in_degree(v) == 1  # B must have exactly one incoming edge
            and any(
                (not G[u][x]["result"]) and G[v][x]["result"]
                for x in set(G.successors(u)) & set(G.successors(v))
            )
        )
    }


def find_merge_candidates_for_or(G):
    """
    Find pairs (u, v) that should be merged based on an OR-like rule:
      - There's a 'dashed' edge (u -> v) => data["result"] == False
      - B (=v) has exactly one incoming edge
      - u and v share at least one successor x where
        both (u->x) and (v->x) are 'solid' => data["result"] == True
    """
    return {
        (u, v)
        for u, v, data in G.edges(data=True)
        if (
            not data["result"]  # 'dashed' edge (u->v)
            and G.in_degree(v) == 1  # B must have exactly one incoming edge
            and any(
                G[u][x]["result"] and G[v][x]["result"]
                for x in set(G.successors(u)) & set(G.successors(v))
            )
        )
    }


def find_merge_candidates_for_and(G):
    """
    Find pairs (u, v) that should be merged based on an AND-like rule:
      - There's a 'solid' edge (u -> v) => data["result"] == True
      - B (=v) has exactly one incoming edge
      - u and v share at least one successor x where
        both (u->x) and (v->x) are 'dashed' => data["result"] == False
    """
    return {
        (u, v)
        for u, v, data in G.edges(data=True)
        if (
            data["result"]  # 'solid' edge (u->v)
            and G.in_degree(v) == 1  # B must have exactly one incoming edge
            and any(
                (not G[u][x]["result"]) and (not G[v][x]["result"])
                for x in set(G.successors(u)) & set(G.successors(v))
            )
        )
    }


def merge_pair(G, A, B, new_node):
    """
    Merge nodes A and B into a new node named new_node.

    - All inbound edges to A or B become inbound edges to new_node.
    - All outbound edges from A or B become outbound edges from new_node.
    - Removes A and B from the graph.
    - Removes any self-loop on new_node.
    """
    G.add_node(new_node)

    # Redirect inbound edges
    predecessors = set(G.predecessors(A)) | set(G.predecessors(B))
    for p in predecessors:
        if G.has_edge(p, A):
            G.add_edge(p, new_node, **G[p][A])
        if G.has_edge(p, B):
            G.add_edge(p, new_node, **G[p][B])

    # Redirect outbound edges
    successors = set(G.successors(A)) | set(G.successors(B))
    for s in successors:
        if G.has_edge(A, s):
            G.add_edge(new_node, s, **G[A][s])
        if G.has_edge(B, s):
            G.add_edge(new_node, s, **G[B][s])

    # Remove the original nodes
    G.remove_nodes_from([A, B])

    # Remove possible self-loop
    if G.has_edge(new_node, new_node):
        G.remove_edge(new_node, new_node)


def merge_candidates_into_not_or(G):
    """
    Keep merging nodes in G according to the NOT-OR rule until
    no more merges are possible. Returns True if any merges happened,
    False otherwise.
    """
    changed = False
    while merge_pairs := find_merge_candidates_for_not_or(G):
        changed = True
        for A, B in merge_pairs:
            if A in G and B in G:
                merge_pair(G, A, B, new_node=f"or(not({A}),{B})")
    return changed


def merge_candidates_into_or(G):
    """
    Keep merging nodes in G according to the OR-like rule until
    no more merges are possible. Returns True if any merges happened,
    False otherwise.
    """
    changed = False
    while merge_pairs := find_merge_candidates_for_or(G):
        changed = True
        for A, B in merge_pairs:
            if A in G and B in G:
                merge_pair(G, A, B, new_node=f"or({A},{B})")
    return changed


def merge_nodes_into_and(G):
    """
    Keep merging nodes in G according to the AND-like rule until
    no more merges are possible. Returns True if any merges happened,
    False otherwise.
    """
    changed = False
    while candidates := find_merge_candidates_for_and(G):
        changed = True
        for A, B in candidates:
            if A in G and B in G:
                merge_pair(G, A, B, new_node=f"and({A},{B})")
    return changed


def merge_nodes_into_not_and(G):
    """
    Keep merging nodes in G according to the AND-like rule until
    no more merges are possible. Returns True if any merges happened,
    False otherwise.
    """
    changed = False
    while candidates := find_merge_candidates_for_not_and(G):
        changed = True
        for A, B in candidates:
            if A in G and B in G:
                merge_pair(G, A, B, new_node=f"and(not({A}),{B})")
    return changed


# add rule for chains


def merger(G):
    """
    Orchestrates repeated merges on the graph G using:
      - OR-like rule,
      - AND-like rule,
      - NOT-OR rule,
    until no further merges are possible.
    """
    while True:
        # If no merges of any type happen in an iteration, we're done.
        if not (
            merge_candidates_into_or(G)
            or merge_nodes_into_and(G)
            or merge_candidates_into_not_or(G)
            or merge_nodes_into_not_and(G)
        ):
            break
