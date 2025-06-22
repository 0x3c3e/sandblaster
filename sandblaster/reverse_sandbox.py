import sys
import logging
import argparse
from sandbox_data import SandboxData


from nodes import operation_node_builder


def process_profile(outfname: str, sandbox_data: SandboxData):
    with open(outfname, "wt") as outfile:
        default_node = (
            sandbox_data.payload.operation_nodes.find_operation_node_by_offset(
                sandbox_data.payload.op_table[0]
            )
        )
        if not default_node or not default_node.node:
            return

        outfile.write("(version 1)\n")

        for idx, offset in enumerate(sandbox_data.payload.op_table):
            operation = sandbox_data.payload.sb_ops[idx]
            if sandbox_data.payload.ops_to_reverse and (
                operation not in sandbox_data.payload.ops_to_reverse
            ):
                continue
            node = sandbox_data.payload.operation_nodes.find_operation_node_by_offset(
                offset
            )
            if not node:
                continue

            graph_builder = operation_node_builder.OperationNodeGraphBuilder(node)
            graph = graph_builder.build_operation_node_graph()

            for node in graph.nodes:
                n = sandbox_data.payload.operation_nodes.find_operation_node_by_offset(
                    node
                )
                print(node, n, n.raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Path to the binary sandbox profile.")
    parser.add_argument(
        "-o", "--operations_file", required=True, help="File with list of operations."
    )
    parser.add_argument("-n", "--operation", nargs="+", help="Operation(s) to reverse.")
    parser.add_argument("--output", help="Output path", required=True)
    args = parser.parse_args()

    with open(args.filename, "rb") as infile:
        sandbox_data = SandboxData.from_file(infile)

        sandbox_data.payload.read_sandbox_operations(args.operations_file)
        logging.info(f"Read {len(sandbox_data.payload.sb_ops)} sandbox operations")

        if args.operation:
            sandbox_data.payload.filter_sandbox_operations(args.operation)
            logging.info(f"Filtered by {args.operation} sandbox operations")

        sandbox_data.payload.parse_regex_list(
            infile,
            sandbox_data.regex_count,
            sandbox_data.regex_table_offset,
            sandbox_data.base_addr,
        )
        logging.info(f"Regex list length: {len(sandbox_data.payload.regex_list)}")

        sandbox_data.payload.parse_global_vars(
            infile,
            sandbox_data.vars_offset,
            sandbox_data.vars_count,
            sandbox_data.base_addr,
        )
        logging.info(f"Global variables are: {sandbox_data.payload.global_vars}")

        sandbox_data.payload.parse_policies(
            infile, sandbox_data.entitlements_offset, sandbox_data.entitlements_count
        )

        infile.seek(sandbox_data.operation_nodes_offset)
        logging.info(f"Number of operation nodes: {sandbox_data.op_nodes_count}")
        sandbox_data.payload.create_operation_nodes(
            infile, sandbox_data.op_nodes_count, sandbox_data
        )

        infile.seek(sandbox_data.profiles_offset)
        sandbox_data.payload.parse_op_table(infile, sandbox_data.sb_ops_count)

        infile.seek(sandbox_data.operation_nodes_offset)
        process_profile(args.output, sandbox_data)

    logging.info("Processing complete.")


if __name__ == "__main__":
    sys.exit(main())
