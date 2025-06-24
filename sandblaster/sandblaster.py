import sys
import argparse
from parsers.header import SandboxHeader
from parsers.profile import SandboxPayload
from nodes import operation_node_builder
from configs.filters import Filters


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

            graph_builder = operation_node_builder.OperationNodeGraphBuilder(node)
            graph = graph_builder.build_operation_node_graph()

            graph_builder.export_dot("../dots/out.dot")
            for graph_node_offset in graph.nodes:
                graph_node = payload.operation_nodes.find_operation_node_by_offset(
                    graph_node_offset
                )
                if graph_node:
                    print(
                        graph_node_offset, graph_node, getattr(graph_node, "raw", None)
                    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sandbox profile operation graph builder."
    )
    parser.add_argument("filename", help="Path to the binary sandbox profile.")
    parser.add_argument(
        "-o",
        "--operations_file",
        required=True,
        help="File listing supported operations.",
    )
    parser.add_argument(
        "-n", "--operation", nargs="+", help="Operation(s) to reverse (optional)."
    )
    parser.add_argument(
        "--output", required=True, help="Path to write the output file."
    )

    args = parser.parse_args()

    filters = Filters("./misc/filters.json")
    modifiers = Filters("./misc/modifiers_functions.json")
    terminals = Filters("./misc/modifiers.json")
    with open(args.filename, "rb") as infile:
        sandbox_data = SandboxHeader.from_file(infile)
        payload = SandboxPayload(infile=infile, base_addr=sandbox_data.base_addr)
        payload.parse(
            sandbox_data,
            args.operations_file,
            args.operation,
            filters,
            modifiers,
            terminals,
        )

    process_profile(args.output, payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
