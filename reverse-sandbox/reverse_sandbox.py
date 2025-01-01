#!/usr/bin/env python

import sys
import struct
import logging.config
import argparse
import pprint
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import sandbox_filter
import sandbox_regex
from nodes import operation_node_builder
from nodes import operation_node_parser
import graph as gparse

logger = logging.getLogger(__name__)

REGEX_TABLE_OFFSET = 2
REGEX_COUNT_OFFSET = 4
VARS_TABLE_OFFSET = 6
VARS_COUNT_OFFSET = 8
NUM_PROFILES_OFFSET = 10
PROFILE_OPS_OFFSET = 4
OPERATION_NODE_SIZE = 8
INDEX_SIZE = 2


@dataclass
class SandboxData:
    header_size: int
    type: int
    op_nodes_count: int
    sb_ops_count: int
    vars_count: int
    regex_count: int
    states_count: int = field(default=0)
    num_profiles: int = field(default=0)
    entitlements_count: int = field(default=0)
    instructions_count: int = field(default=0)
    op_table: int = field(default=None)
    builder: int = field(default=None)

    regex_table_offset: int = field(init=False)
    vars_offset: int = field(init=False)
    states_offset: int = field(init=False)
    entitlements_offset: int = field(init=False)
    profiles_offset: int = field(init=False)
    profiles_end_offset: int = field(init=False)
    operation_nodes_size: int = field(init=False)
    operation_nodes_offset: int = field(init=False)
    base_addr: int = field(init=False)

    regex_list: Optional[List[str]] = field(default_factory=list)
    global_vars: Optional[List[str]] = field(default_factory=list)
    policies: Optional[Tuple[int]] = field(default=None)
    sb_ops: Optional[List[str]] = field(default_factory=list)
    operation_nodes: Optional[List[object]] = field(default=None)
    ops_to_reverse: Optional[List[str]] = field(default_factory=list)

    def __post_init__(self):
        self.regex_table_offset = self.header_size
        self.vars_offset = self.regex_table_offset + (self.regex_count * INDEX_SIZE)
        self.states_offset = self.vars_offset + (self.vars_count * INDEX_SIZE)
        self.entitlements_offset = self.states_offset + (self.states_count * INDEX_SIZE)
        self.profiles_offset = self.entitlements_offset + (
            self.entitlements_count * INDEX_SIZE
        )
        self.profiles_end_offset = self.profiles_offset + (
            self.num_profiles * (self.sb_ops_count * INDEX_SIZE + PROFILE_OPS_OFFSET)
        )
        self.operation_nodes_size = self.op_nodes_count * OPERATION_NODE_SIZE
        self.operation_nodes_offset = self.profiles_end_offset
        self.operation_nodes_offset += self.sb_ops_count * INDEX_SIZE
        align_delta = self.operation_nodes_offset & 7
        if align_delta != 0:
            self.operation_nodes_offset += 8 - align_delta
        self.base_addr = self.operation_nodes_offset + self.operation_nodes_size

    @classmethod
    def from_file(cls, infile: object) -> "SandboxData":
        macos15_2_struct = struct.Struct("<HHBB6xHH")
        values = macos15_2_struct.unpack(infile.read(macos15_2_struct.size))
        return cls(
            header_size=macos15_2_struct.size,
            type=values[0],
            op_nodes_count=values[1],
            sb_ops_count=values[2],
            vars_count=values[3],
            regex_count=values[4],
        )


def extract_string_from_offset(f: object, offset: int, base_addr: int) -> str:
    f.seek(offset * 8 + base_addr)
    string_len = struct.unpack("<H", f.read(2))[0] - 1
    return f.read(string_len).decode("utf-8")


def create_operation_nodes(
    infile: object, sandbox_data: SandboxData, keep_builtin_filters: bool
) -> List[object]:
    sandbox_data.operation_nodes = operation_node_parser.OperionNodeParser()
    sandbox_data.operation_nodes.build_operation_nodes(
        infile, sandbox_data.op_nodes_count
    )
    for node in sandbox_data.operation_nodes.operation_nodes:
        node.convert_filter(
            sandbox_filter.convert_filter_callback,
            infile,
            sandbox_data,
            keep_builtin_filters,
        )


def process_profile(outfname: str, sandbox_data: SandboxData):
    with open(outfname, "wt") as outfile:
        default_node = sandbox_data.operation_nodes.find_operation_node_by_offset(
            sandbox_data.op_table[0]
        )
        if not default_node or not default_node.terminal:
            logger.warning(
                "Default node or terminal not found; skipping profile processing."
            )
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
            
            node.parse_terminal()
            graph_builder = operation_node_builder.OperationNodeGraphBuilder(node)
            graph = graph_builder.build_operation_node_graph()
            if graph:
                print(operation, graph)
                # sandbox_data.builder.print_recursive_edges(graph, node.offset, 0, outfile)
                # graph_builder.print(sandbox_data.operation_nodes)
                import networkx as nx

                g = graph_builder.build_subgraph_with_edge_style("solid")
                print(g)
                for i, p in enumerate(gparse.get_subgraphs(g)):
                    print(i, p)
                    p = gparse.reduce_graph(p)
                    print(i, p)
                    pydot_graph = nx.drawing.nx_pydot.to_pydot(p)
                    pydot_graph.write_dot(f"gr/graph_{i}.dot")
                # graph_builder.visualize()
                graph_builder.print(g, sandbox_data.operation_nodes)
            else:
                outfile.write(f"({node.terminal} {operation})\n")
                if node.terminal.db_modifiers:
                    modifiers_type = [
                        key for key, val in node.terminal.db_modifiers.items() if val
                    ]
                    if modifiers_type:
                        outfile.write(f"({node.terminal} {operation})\n")


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
            logger.error(f"Unavailable operation: {op}")
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
        regex_data = struct.unpack(f"<{re_length}B", infile.read(re_length))
        sandbox_data.regex_list.append(sandbox_regex.parse_regex(regex_data))


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
    parser.add_argument(
        "-kbf",
        "--keep_builtin_filters",
        action="store_true",
        help="Keep builtin filters.",
    )
    args = parser.parse_args()

    with open(args.filename, "rb") as infile:
        sandbox_data = SandboxData.from_file(infile)
        pprint.pprint(sandbox_data)

        read_sandbox_operations(args.operations_file, sandbox_data)
        logger.info(f"Read {len(sandbox_data.sb_ops)} sandbox operations")

        if args.operation:
            filter_sandbox_operations(args.operation, sandbox_data)
            logger.info(f"Filtered by {args.operation} sandbox operations")

        parse_regex_list(infile, sandbox_data)
        logger.info(f"Regex list length: {len(sandbox_data.regex_list)}")

        parse_global_vars(infile, sandbox_data)
        logger.info(f"Global variables are: {sandbox_data.global_vars}")

        parse_policies(infile, sandbox_data)

        infile.seek(sandbox_data.operation_nodes_offset)
        logger.info(f"Number of operation nodes: {sandbox_data.op_nodes_count}")
        create_operation_nodes(infile, sandbox_data, args.keep_builtin_filters)

        infile.seek(sandbox_data.profiles_offset)
        parse_op_table(infile, sandbox_data)

        infile.seek(sandbox_data.operation_nodes_offset)
        process_profile(args.output, sandbox_data)

    logger.info("Processing complete.")


if __name__ == "__main__":
    sys.exit(main())
