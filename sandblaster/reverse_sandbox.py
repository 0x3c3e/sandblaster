import sys
import struct
import logging
import argparse
from sandbox_data import SandboxData
from typing import List, Tuple


from nodes import operation_node_builder
from nodes import operation_node_parser
import parsers.regex as regex


def create_operation_nodes(infile: object, sandbox_data: SandboxData) -> List[object]:
    sandbox_data.operation_nodes = operation_node_parser.OperionNodeParser()
    sandbox_data.operation_nodes.build_operation_nodes(
        infile, sandbox_data.op_nodes_count, sandbox_data
    )


def process_profile(outfname: str, sandbox_data: SandboxData):
    with open(outfname, "wt") as outfile:
        default_node = sandbox_data.operation_nodes.find_operation_node_by_offset(
            sandbox_data.op_table[0]
        )
        if not default_node or not default_node.node:
            return

        outfile.write("(version 1)\n")

        for idx, offset in enumerate(sandbox_data.op_table):
            operation = sandbox_data.sb_ops[idx]
            if sandbox_data.ops_to_reverse and (
                operation not in sandbox_data.ops_to_reverse
            ):
                continue
            node = sandbox_data.operation_nodes.find_operation_node_by_offset(offset)
            if not node:
                continue

            graph_builder = operation_node_builder.OperationNodeGraphBuilder(node)
            graph = graph_builder.build_operation_node_graph()
            # graph_builder.export_dot("aa.dot")

            for node in graph.nodes:
                n = sandbox_data.operation_nodes.find_operation_node_by_offset(node)
                print(node, n, n.raw)
            # for i, sink in enumerate(sinks):
            #     out = graph_tools.build_ite_iterative_z3(graph, start, sink)
            #     print(graph_tools.ite_expr_to_cnf_z3(out))


def parse_global_vars(f: object, sandbox_data: SandboxData) -> List[str]:
    next_var_pointer = sandbox_data.vars_offset

    for _ in range(sandbox_data.vars_count):
        f.seek(next_var_pointer)
        var_offset = struct.unpack("<H", f.read(2))[0]
        f.seek(sandbox_data.base_addr + (var_offset * 8))
        string_len = struct.unpack("H", f.read(2))[0]
        var_string = f.read(string_len - 1).decode("utf-8")
        sandbox_data.global_vars.append(var_string)
        next_var_pointer += 2


def parse_policies(f: object, sandbox_data: SandboxData) -> Tuple[int]:
    f.seek(sandbox_data.entitlements_offset)
    sandbox_data.policies = struct.unpack(
        f"<{sandbox_data.entitlements_count}H",
        f.read(2 * sandbox_data.entitlements_count),
    )


def read_sandbox_operations(operations_file, sandbox_data: SandboxData):
    with open(operations_file) as file:
        sandbox_data.sb_ops = [line.strip() for line in file.readlines()]


def filter_sandbox_operations(operation, sandbox_data):
    for op in operation:
        if op not in sandbox_data.sb_ops:
            sys.exit(1)
        sandbox_data.ops_to_reverse.append(op)


def parse_regex_list(infile: object, sandbox_data: SandboxData):
    if not sandbox_data.regex_count:
        return

    infile.seek(sandbox_data.regex_table_offset)
    offsets_table = struct.unpack(
        f"<{sandbox_data.regex_count}H",
        infile.read(2 * sandbox_data.regex_count),
    )

    for offset in offsets_table:
        infile.seek(offset * 8 + sandbox_data.base_addr)
        re_length = struct.unpack("<H", infile.read(2))[0]
        data = infile.read(re_length)
        sandbox_data.regex_list.append(regex.analyze(data))


def parse_op_table(infile: object, sandbox_data: SandboxData):
    sandbox_data.op_table = struct.unpack(
        f"<{sandbox_data.sb_ops_count}H",
        infile.read(2 * sandbox_data.sb_ops_count),
    )


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

        read_sandbox_operations(args.operations_file, sandbox_data)
        logging.info(f"Read {len(sandbox_data.sb_ops)} sandbox operations")

        if args.operation:
            filter_sandbox_operations(args.operation, sandbox_data)
            logging.info(f"Filtered by {args.operation} sandbox operations")

        parse_regex_list(infile, sandbox_data)
        logging.info(f"Regex list length: {len(sandbox_data.regex_list)}")

        parse_global_vars(infile, sandbox_data)
        logging.info(f"Global variables are: {sandbox_data.global_vars}")

        parse_policies(infile, sandbox_data)

        infile.seek(sandbox_data.operation_nodes_offset)
        logging.info(f"Number of operation nodes: {sandbox_data.op_nodes_count}")
        create_operation_nodes(infile, sandbox_data)

        infile.seek(sandbox_data.profiles_offset)
        parse_op_table(infile, sandbox_data)

        infile.seek(sandbox_data.operation_nodes_offset)
        process_profile(args.output, sandbox_data)

    logging.info("Processing complete.")


if __name__ == "__main__":
    sys.exit(main())
