#!/usr/bin/env python

import sys
import struct
import logging.config
import argparse
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import operation_node
import sandbox_filter
import sandbox_regex

logging.config.fileConfig("logger.config")
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
    states_count: int
    num_profiles: int
    regex_count: int
    entitlements_count: int
    instructions_count: int
    data_file: Optional[object] = field(default=None)

    regex_table_offset: int = field(init=False)
    vars_offset: int = field(init=False)
    states_offset: int = field(init=False)
    entitlements_offset: int = field(init=False)
    profiles_offset: int = field(init=False)
    profiles_end_offset: int = field(init=False)
    operation_nodes_size: int = field(init=False)
    operation_nodes_offset: int = field(init=False)
    base_addr: int = field(init=False)

    regex_list: Optional[List[str]] = field(default=None)
    global_vars: Optional[List[str]] = field(default=None)
    policies: Optional[Tuple[int]] = field(default=None)
    sb_ops: Optional[List[str]] = field(default=None)
    operation_nodes: Optional[List[object]] = field(default=None)
    ops_to_reverse: Optional[List[str]] = field(default=None)

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
        infile.seek(0)
        macos15_2_struct = struct.Struct("<HHBBBxHHHH")
        values = macos15_2_struct.unpack(infile.read(macos15_2_struct.size))
        return cls(
            header_size=macos15_2_struct.size,
            type=values[0],
            op_nodes_count=values[1],
            sb_ops_count=values[2],
            vars_count=values[3],
            states_count=values[4],
            num_profiles=values[5],
            regex_count=values[7],
            entitlements_count=values[6],
            instructions_count=values[8],
            data_file=infile,
        )


def extract_string_from_offset(f: object, offset: int, base_addr: int) -> str:
    f.seek(offset * 8 + base_addr)
    string_len = struct.unpack("<H", f.read(2))[0] - 1
    return f.read(string_len).decode("utf-8")


def create_operation_nodes(
    infile: object, sandbox_data: SandboxData, keep_builtin_filters: bool
) -> List[object]:
    sandbox_data.operation_nodes = operation_node.build_operation_nodes(
        infile, sandbox_data.op_nodes_count
    )
    logger.info(f"Built {len(sandbox_data.operation_nodes)} operation nodes")

    for node in sandbox_data.operation_nodes:
        node.convert_filter(
            sandbox_filter.convert_filter_callback,
            infile,
            sandbox_data,
            keep_builtin_filters,
        )
    logger.info("Operation nodes after filter conversion")
    return sandbox_data.operation_nodes


def process_profile(
    outfname: str,
    sb_ops: List[str],
    ops_to_reverse: List[str],
    op_table: List[int],
    operation_nodes: List[object],
):
    out_fname = f"{outfname.strip()}.sb"
    with open(out_fname, "wt") as outfile:
        default_node = operation_node.find_operation_node_by_offset(
            operation_nodes, op_table[0]
        )
        if not default_node or not default_node.terminal:
            logger.warning(
                "Default node or terminal not found; skipping profile processing."
            )
            return

        outfile.write("(version 1)\n")
        outfile.write(f"({default_node.terminal} default)\n")

        for idx in range(1, len(op_table)):
            offset = op_table[idx]
            operation = sb_ops[idx]
            if ops_to_reverse and (operation not in ops_to_reverse):
                continue

            node = operation_node.find_operation_node_by_offset(operation_nodes, offset)
            if not node:
                continue

            graph = operation_node.build_operation_node_graph(node, default_node)
            if graph:
                reduced_graph = operation_node.reduce_operation_node_graph(graph)
                reduced_graph.str_simple_with_metanodes()
                reduced_graph.print_vertices_with_operation_metanodes(
                    operation, default_node.terminal.is_allow(), outfile
                )
            elif node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    outfile.write(f"({node.terminal} {operation})\n")
                elif node.terminal.db_modifiers:
                    modifiers_type = [
                        key for key, val in node.terminal.db_modifiers.items() if val
                    ]
                    if modifiers_type:
                        outfile.write(f"({node.terminal} {operation})\n")


def get_global_vars(
    f: object, vars_offset: int, num_vars: int, base_address: int
) -> List[str]:
    global_vars = []
    next_var_pointer = vars_offset

    for _ in range(num_vars):
        f.seek(next_var_pointer)
        var_offset = struct.unpack("<H", f.read(2))[0]
        f.seek(base_address + (var_offset * 8))
        string_len = struct.unpack("H", f.read(2))[0]
        var_string = f.read(string_len - 1).decode("utf-8")
        global_vars.append(var_string)
        next_var_pointer += 2

    logger.info(f"Global variables are: {', '.join(global_vars)}")
    return global_vars


def get_policies(f: object, offset: int, count: int) -> Tuple[int]:
    f.seek(offset)
    return struct.unpack(f"<{count}H", f.read(2 * count))


def read_sandbox_operations(
    parser: argparse.ArgumentParser, args: argparse.Namespace, sandbox_data: SandboxData
):
    sb_ops = [line.strip() for line in open(args.operations_file)]
    sandbox_data.sb_ops = sb_ops
    logger.info(f"Read {len(sb_ops)} sandbox operations")

    ops_to_reverse = []
    if args.operation:
        for op in args.operation:
            if op not in sb_ops:
                parser.print_usage()
                logger.error(f"Unavailable operation: {op}")
                sys.exit(1)
            ops_to_reverse.append(op)
        sandbox_data.ops_to_reverse = ops_to_reverse


def parse_regex_list(infile: object, sandbox_data: SandboxData):
    regex_list = []

    if sandbox_data.regex_count > 0:
        infile.seek(sandbox_data.regex_table_offset)
        offsets_table = struct.unpack(
            f"<{sandbox_data.regex_count}H",
            infile.read(2 * sandbox_data.regex_count),
        )

        for offset in offsets_table:
            infile.seek(offset * 8 + sandbox_data.base_addr)
            re_length = struct.unpack("<H", infile.read(2))[0]
            regex_data = struct.unpack(f"<{re_length}B", infile.read(re_length))
            regex_list.append(sandbox_regex.parse_regex(regex_data))

    logger.info(f"Regex list: {regex_list}")
    sandbox_data.regex_list = regex_list


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Path to the binary sandbox profile.")
    parser.add_argument(
        "-o", "--operations_file", required=True, help="File with list of operations."
    )
    parser.add_argument(
        "-p", "--profile", nargs="+", help="Profile(s) to reverse (for bundles)."
    )
    parser.add_argument("-n", "--operation", nargs="+", help="Operation(s) to reverse.")
    parser.add_argument(
        "-d", "--directory", help="Directory for reversed profiles output."
    )
    parser.add_argument(
        "-kbf",
        "--keep_builtin_filters",
        action="store_true",
        help="Keep builtin filters.",
    )
    args = parser.parse_args()

    if not args.filename:
        parser.print_usage()
        logger.error("No sandbox profile/bundle file specified.")
        sys.exit(1)

    out_dir = args.directory or os.getcwd()

    with open(args.filename, "rb") as infile:
        sandbox_data = SandboxData.from_file(infile)

        read_sandbox_operations(parser, args, sandbox_data)
        parse_regex_list(infile, sandbox_data)

        logger.info(
            f"{sandbox_data.vars_count} global vars at offset {hex(sandbox_data.vars_offset)}"
        )
        sandbox_data.global_vars = get_global_vars(
            infile,
            sandbox_data.vars_offset,
            sandbox_data.vars_count,
            sandbox_data.base_addr,
        )

        sandbox_data.policies = get_policies(
            infile, sandbox_data.entitlements_offset, sandbox_data.entitlements_count
        )

        infile.seek(sandbox_data.operation_nodes_offset)
        logger.info(f"Number of operation nodes: {sandbox_data.op_nodes_count}")
        create_operation_nodes(infile, sandbox_data, args.keep_builtin_filters)

        infile.seek(sandbox_data.profiles_offset)
        op_table = struct.unpack(
            f"<{sandbox_data.sb_ops_count}H",
            infile.read(2 * sandbox_data.sb_ops_count),
        )

        infile.seek(sandbox_data.operation_nodes_offset)
        out_fname = os.path.join(
            out_dir, os.path.splitext(os.path.basename(args.filename))[0]
        )
        process_profile(
            out_fname,
            sandbox_data.sb_ops,
            sandbox_data.ops_to_reverse,
            op_table,
            sandbox_data.operation_nodes,
        )

    logger.info("Processing complete.")


if __name__ == "__main__":
    sys.exit(main())
