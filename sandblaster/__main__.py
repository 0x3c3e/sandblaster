import argparse
import os
from sandblaster.parsers.header import SandboxHeader
from sandblaster.parsers.profile import SandboxPayload
from sandblaster.parsers.graph import GraphParser
from sandblaster.configs.filters import Filters


def process_profile(output_path: str, payload: SandboxPayload) -> None:
    """
    Build and output the operation node graphs for selected operations.
    """
    with open(output_path, "wt") as outfile:
        outfile.write("(version 1)\n")

        for idx, offset in enumerate(payload.op_table):
            operation = payload.sb_ops[idx]

            # Filter if specific operations are requested
            if payload.ops_to_reverse and operation not in payload.ops_to_reverse:
                continue

            node = payload.operation_nodes.find_operation_node_by_offset(offset)
            if not node:
                continue

            graph_builder = GraphParser(node)
            graph = graph_builder.build_operation_node_graph()

            # graph_builder.export_dot("../dots/out.dot")
            for graph_node_offset in graph.nodes:
                graph_node = payload.operation_nodes.find_operation_node_by_offset(
                    graph_node_offset
                )
                if graph_node:
                    print(graph_node_offset, graph_node, graph_node.raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="Apple Sandbox Profiles Decompiler")
    parser.add_argument("filename")
    parser.add_argument(
        "--operations",
        required=True,
    )
    parser.add_argument("--filter")
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    directory = os.path.abspath(os.path.dirname(__file__))
    filters = Filters(directory + "/misc/filters.json")
    modifiers = Filters(directory + "/misc/modifiers.json")
    with open(args.filename, "rb") as infile:
        sandbox_data = SandboxHeader.from_file(infile)
        payload = SandboxPayload(infile=infile, base_addr=sandbox_data.base_addr)
        payload.parse(sandbox_data, args.operations, args.filter, filters, modifiers)

    process_profile(args.output, payload)
    return 0


if __name__ == "__main__":
    main()
