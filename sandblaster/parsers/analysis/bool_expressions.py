import random

import networkx as nx
import z3
from networkx.drawing.nx_pydot import write_dot

from sandblaster.nodes.representation.non_terminal import NonTerminalRepresentation
from sandblaster.parsers.analysis.expression import build_ite_expr, ite_expr_to_nnf
from sandblaster.parsers.analysis.partition import backward_partition
from sandblaster.parsers.core.profile import SandboxPayload
from sandblaster.parsers.graph.graph_parser import GraphParser


def random_hex_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))


def get_nnf_forms(graph, payload, filters):
    partitions = backward_partition(graph, payload)
    sinks = [n for n in nx.topological_sort(graph) if graph.out_degree(n) == 0]
    k = []
    for s in sinks:
        for pred in graph.predecessors(s):
            k.append(pred)
    nx.set_node_attributes(graph, {node: "dashed" for node in k}, "style")

    for i, k in enumerate(partitions.keys()):
        color = random_hex_color()
        nx.set_node_attributes(
            graph, {node: color for node in partitions[k].nodes()}, "color"
        )
        nx.set_node_attributes(
            graph, {node: i for node in partitions[k].nodes()}, "group"
        )
    nx.set_node_attributes(graph, {node: "bold" for node in sinks}, "style")
    write_dot(graph, "out.dot")
    return partitions


def z3_to_sbpl_print(expr, payload, filters, mapping, level=0, output_func=print):
    """
    Recursively prints a Z3 expression in SBPL syntax using match/case on operator type.
    """
    indent = " " * level

    def emit(line: str):
        output_func(f"{indent}{line}")

    decl_kind = expr.decl().kind()
    args = expr.children()

    match decl_kind:
        case z3.Z3_OP_TRUE:
            emit("allow")
        case z3.Z3_OP_FALSE:
            emit("deny")
        case z3.Z3_OP_AND:
            emit("(require-all")
            for arg in args:
                z3_to_sbpl_print(arg, payload, filters, mapping, level + 2, output_func)
            emit(")")

        case z3.Z3_OP_OR:
            emit("(require-any")
            for arg in args:
                z3_to_sbpl_print(arg, payload, filters, mapping, level + 2, output_func)
            emit(")")

        case z3.Z3_OP_NOT:
            emit("(require-not")
            z3_to_sbpl_print(args[0], payload, filters, mapping, level + 2, output_func)
            emit(")")

        case z3.Z3_OP_ITE:
            emit("(if")
            z3_to_sbpl_print(
                args[0], payload, filters, mapping, level + 2, output_func
            )  # condition
            z3_to_sbpl_print(
                args[1], payload, filters, mapping, level + 2, output_func
            )  # then
            z3_to_sbpl_print(
                args[2], payload, filters, mapping, level + 2, output_func
            )  # else
            emit(")")
        case z3.Z3_OP_UNINTERPRETED:
            name = expr.decl().name()
            offset = mapping[name]
            node = payload.operation_nodes.find_operation_node_by_offset(offset)
            emit(str(NonTerminalRepresentation(node, filters)))

        case _:
            raise ValueError(
                f"Unsupported Z3 expression: {expr} (decl kind: {decl_kind})"
            )


def process_profile(payload: SandboxPayload, filters, modifier_resolver) -> None:
    for idx in payload.ops_to_reverse:
        sb_op = payload.sb_ops[idx]
        offset = payload.op_table[idx]
        node = payload.operation_nodes.find_operation_node_by_offset(offset)
        if not node:
            continue

        print(sb_op)

        graph_parser = GraphParser(node)
        graph = graph_parser.parse()
        mapping = graph_parser.mapping

        nnf_forms = get_nnf_forms(graph, payload, filters)

        for key, subgraph in nnf_forms.items():
            exprs = []

            for start_node in [n for n, deg in subgraph.in_degree() if deg == 0]:
                ite_expr = build_ite_expr(subgraph, start_node)
                nnf_expr = ite_expr_to_nnf(ite_expr)
                exprs.append(nnf_expr)

            merged_expr = z3.Or(*exprs)
            final_expr = ite_expr_to_nnf(merged_expr)

            print(key, final_expr)
            z3_to_sbpl_print(final_expr, payload, filters, mapping)
            print("*" * 10)
