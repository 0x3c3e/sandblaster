import networkx as nx
import z3


def build_ite_iterative_z3(G, start_node, sink):
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
        if G.out_degree(node) == 0 and node == sink:
            node_to_expr[node] = z3.BoolVal(True)
            continue
        if G.out_degree(node) == 0 and node != sink:
            node_to_expr[node] = z3.BoolVal(False)
            continue
        # Interpret the node's label as a Z3 Boolean variable.
        label_str = f"{G.nodes[node].get('label')}"
        condition = z3.Bool(label_str)

        # Identify the child for result=1 (true branch) and result=0 (false branch).
        true_succ_expr = None
        false_succ_expr = None
        for _, tgt, data in G.out_edges(node, data=True):
            if data["result"]:
                true_succ_expr = node_to_expr[tgt]
            else:
                false_succ_expr = node_to_expr[tgt]

        node_to_expr[node] = z3.If(condition, true_succ_expr, false_succ_expr)

    # Finally, return the expression for 'start_node' as the top-level ITE.
    return ite_expr_to_cnf_z3(node_to_expr[start_node])


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
