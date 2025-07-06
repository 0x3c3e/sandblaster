import random

import networkx as nx
import z3
from networkx.drawing.nx_pydot import write_dot

from sandblaster.nodes.representation.non_terminal import NonTerminalRepresentation
from sandblaster.nodes.representation.terminal import TerminalNodeRepresentation
from sandblaster.parsers.analysis.expression import build_ite_expr, ite_expr_to_nnf
from sandblaster.parsers.analysis.partition import backward_partition
from sandblaster.parsers.core.profile import SandboxPayload
from sandblaster.parsers.graph.graph_parser import GraphParser
from sandblaster.parsers.analysis.spbl_printer import z3_to_sbpl_print


def random_hex_color(seed=None):
    rng = random.Random(seed)
    return "#{:06x}".format(rng.randint(0, 0xFFFFFF))


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


def get_parsed_nodes(graph, parsed: dict, filters) -> dict:
    unparsed_nodes = {
        n
        for n in nx.topological_sort(graph)
        if graph.out_degree(n) != 0 and str(n) not in parsed
    }

    new_entries = {
        str(graph.nodes[n]["id"]): NonTerminalRepresentation(
            *graph.nodes[n]["id"], filters
        )
        for n in unparsed_nodes
    }

    parsed.update(new_entries)
    return parsed


def process_profile(
    payload: SandboxPayload, filters, modifier_resolver, terminal_resolver
) -> None:
    parsed = {}
    for idx in payload.ops_to_reverse:
        sb_op = payload.sb_ops[idx]
        offset = payload.op_table[idx]
        node = payload.operation_nodes.find_operation_node_by_offset(offset)
        if not node:
            continue

        parsed = _process_graph_from_node(
            node, payload, filters, parsed, modifier_resolver, terminal_resolver, sb_op
        )
        print("*" * 10)


def _process_graph_from_node(
    node, payload, filters, parsed, modifier_resolver, terminal_resolver, sb_op
) -> dict:
    graph_parser = GraphParser(node)
    graph = graph_parser.parse()
    parsed = get_parsed_nodes(graph, parsed, filters)
    nnf_forms = get_nnf_forms(graph, payload, filters)

    for key, subgraph in nnf_forms.items():
        _process_subgraph(
            subgraph,
            key,
            payload,
            filters,
            parsed,
            modifier_resolver,
            terminal_resolver,
            sb_op,
        )

    return parsed


def _process_subgraph(
    subgraph, key, payload, filters, parsed, modifier_resolver, terminal_resolver, sb_op
):
    exprs = [
        ite_expr_to_nnf(build_ite_expr(subgraph, start_node))
        for start_node, deg in subgraph.in_degree()
        if deg == 0
    ]

    merged_expr = z3.Or(*exprs)
    final_expr = ite_expr_to_nnf(merged_expr)

    terminal = payload.operation_nodes.find_operation_node_by_offset(key)
    terminal_repr = TerminalNodeRepresentation(
        terminal, terminal_resolver, modifier_resolver, payload, sb_op
    )
    print(terminal_repr)
    z3_to_sbpl_print(final_expr, payload, filters, parsed, level=1)
    print(")")
