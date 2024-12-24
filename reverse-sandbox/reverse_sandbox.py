#!/usr/bin/env python

import sys
import struct
import logging.config
import argparse
import os
from dataclasses import dataclass, field

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

macos15_2_struct = struct.Struct("<HHBBBxHHHH")


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
    data_file: object = field(default=None)
    regex_table_offset: int = field(init=False)
    vars_offset: int = field(init=False)
    states_offset: int = field(init=False)
    entitlements_offset: int = field(init=False)
    profiles_offset: int = field(init=False)
    profiles_end_offset: int = field(init=False)
    operation_nodes_size: int = field(init=False)
    operation_nodes_offset: int = field(init=False)
    base_addr: int = field(init=False)
    regex_list: list = field(default=None)
    global_vars: list = field(default=None)
    policies: tuple = field(default=None)
    sb_ops: list = field(default=None)
    operation_nodes: list = field(default=None)
    ops_to_reverse: list = field(default=None)

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
        if not self.type:  # non-bundle file
            self.operation_nodes_offset += self.sb_ops_count * INDEX_SIZE
        align_delta = self.operation_nodes_offset & 7
        if align_delta != 0:
            self.operation_nodes_offset += 8 - align_delta
        self.base_addr = self.operation_nodes_offset + self.operation_nodes_size


def parse_profile(infile):
    infile.seek(0)
    (
        header,
        op_nodes_count,
        sb_ops_count,
        vars_count,
        states_count,
        num_profiles,
        entitlements_count,
        re_count,
        instructions_count,
    ) = macos15_2_struct.unpack(infile.read(macos15_2_struct.size))
    sandbox_data = SandboxData(
        macos15_2_struct.size,
        header,
        op_nodes_count,
        sb_ops_count,
        vars_count,
        states_count,
        num_profiles,
        re_count,
        entitlements_count,
        instructions_count,
    )
    sandbox_data.data_file = infile
    print(sandbox_data)
    return sandbox_data


def extract_string_from_offset(f, offset, base_addr):
    f.seek(offset * 8 + base_addr)
    string_len = struct.unpack("<H", f.read(2))[0] - 1
    return f.read(string_len).decode("utf-8")


def create_operation_nodes(infile, sandbox_data, keep_builtin_filters):
    sandbox_data.operation_nodes = operation_node.build_operation_nodes(
        infile, sandbox_data.op_nodes_count
    )
    logger.info("operation nodes")
    for op_node in sandbox_data.operation_nodes:
        op_node.convert_filter(
            sandbox_filter.convert_filter_callback,
            infile,
            sandbox_data,
            keep_builtin_filters,
        )
    logger.info("operation nodes after filter conversion")
    return sandbox_data.operation_nodes


def process_profile(outfname, sb_ops, ops_to_reverse, op_table, operation_nodes):
    out_fname = os.path.join(outfname.strip() + ".sb")
    outfile = open(out_fname, "wt")

    default_node = operation_node.find_operation_node_by_offset(
        operation_nodes, op_table[0]
    )
    if not default_node.terminal:
        return

    outfile.write("(version 1)\n")
    outfile.write("(%s default)\n" % (default_node.terminal))

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
        else:
            if not node.terminal:
                continue
            if node.terminal.type != default_node.terminal.type:
                outfile.write("(%s %s)\n" % (node.terminal, operation))
            else:
                if not node.terminal.db_modifiers:
                    continue
                modifiers_type = [
                    key for key, val in node.terminal.db_modifiers.items() if len(val)
                ]
                if modifiers_type:
                    outfile.write("(%s %s)\n" % (node.terminal, operation))
    outfile.close()


def get_global_vars(f, vars_offset, num_vars, base_address):
    global_vars = []
    next_var_pointer = vars_offset
    for _ in range(num_vars):
        f.seek(next_var_pointer)
        var_offset = struct.unpack("<H", f.read(2))[0]
        f.seek(base_address + (var_offset * 8))
        string_len = struct.unpack("H", f.read(2))[0]
        s = f.read(string_len - 1).decode("utf-8")
        global_vars.append(s)
        next_var_pointer += 2
    logger.info("global variables are %s", ", ".join(global_vars))
    return global_vars


def get_policies(f, offset, count):
    f.seek(offset)
    return struct.unpack("<%dH" % count, f.read(2 * count))


def read_sandbox_operations(parser, args, sandbox_data):
    sb_ops = [l.strip() for l in open(args.operations_file)]
    sandbox_data.sb_ops = sb_ops
    logger.info("num_sb_ops: %d", len(sb_ops))
    ops_to_reverse = []
    if args.operation:
        for op in args.operation:
            if op not in sb_ops:
                parser.print_usage()
                print("unavailable operation: {}".format(op))
                sys.exit(1)
            ops_to_reverse.append(op)
        sandbox_data.ops_to_reverse = ops_to_reverse


def parse_regex_list(infile, sandbox_data):
    logger.debug("regular expressions:")
    regex_list = []
    if sandbox_data.regex_count > 0:
        infile.seek(sandbox_data.regex_table_offset)
        re_offsets_table = struct.unpack(
            "<%dH" % sandbox_data.regex_count, infile.read(2 * sandbox_data.regex_count)
        )
        for offset in re_offsets_table:
            infile.seek(offset * 8 + sandbox_data.base_addr)
            re_length = struct.unpack("<H", infile.read(2))[0]
            regex_data = struct.unpack("<%dB" % re_length, infile.read(re_length))
            logger.debug("re: [%s]", ", ".join([hex(i) for i in regex_data]))
            regex_list.append(sandbox_regex.parse_regex(regex_data))
    logger.info(regex_list)
    sandbox_data.regex_list = regex_list


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="path to the binary sandbox profile")
    parser.add_argument(
        "-o", "--operations_file", required=True, help="file with list of operations"
    )
    parser.add_argument(
        "-p", "--profile", nargs="+", help="profile(s) to reverse (for bundles)"
    )
    parser.add_argument("-n", "--operation", nargs="+", help="operation(s) to reverse")
    parser.add_argument(
        "-d", "--directory", help="directory for reversed profiles output"
    )
    parser.add_argument("-kbf", "--keep_builtin_filters", action="store_true")
    args = parser.parse_args()

    if not args.filename:
        parser.print_usage()
        print("no sandbox profile/bundle file to reverse")
        sys.exit(1)

    out_dir = args.directory if args.directory else os.getcwd()
    infile = open(args.filename, "rb")
    sandbox_data = parse_profile(infile)
    read_sandbox_operations(parser, args, sandbox_data)
    parse_regex_list(infile, sandbox_data)

    logger.info(
        "%d global vars at offset %s",
        sandbox_data.vars_count,
        hex(sandbox_data.vars_offset),
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
    logger.info("number of operation nodes: %u", sandbox_data.op_nodes_count)
    operation_nodes = create_operation_nodes(
        infile, sandbox_data, args.keep_builtin_filters
    )

    infile.seek(sandbox_data.profiles_offset)
    op_table = struct.unpack(
        "<%dH" % sandbox_data.sb_ops_count,
        infile.read(2 * sandbox_data.sb_ops_count),
    )
    infile.seek(sandbox_data.operation_nodes_offset)
    logger.info("number of operation nodes: %d", sandbox_data.op_nodes_count)
    out_fname = os.path.join(
        out_dir, os.path.splitext(os.path.basename(args.filename))[0]
    )
    process_profile(
        out_fname,
        sandbox_data.sb_ops,
        sandbox_data.ops_to_reverse,
        op_table,
        operation_nodes,
    )

    infile.close()


if __name__ == "__main__":
    sys.exit(main())
