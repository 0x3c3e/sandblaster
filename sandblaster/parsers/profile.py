from dataclasses import dataclass, field
from typing import List, Tuple, Optional, BinaryIO
import struct
import sys
import logging

import parsers.regex as regex
from nodes import operation_node_parser
from filters.filter_resolver import FilterResolver
from filters.modifier_resolver import ModifierResolver


@dataclass(slots=True)
class SandboxPayload:
    infile: BinaryIO
    base_addr: int

    op_table: Optional[Tuple[int, ...]] = None
    regex_list: List[str] = field(default_factory=list)
    global_vars: List[str] = field(default_factory=list)
    policies: Optional[Tuple[int, ...]] = None
    sb_ops: List[str] = field(default_factory=list)
    operation_nodes: Optional[object] = None
    ops_to_reverse: List[str] = field(default_factory=list)

    def parse(
        self,
        sandbox_data: object,
        operations_file: str,
        operation_filter: Optional[List[str]],
        filters,
        modifiers,
    ) -> None:
        self._read_sandbox_operations(operations_file)
        if operation_filter:
            self._filter_operations(operation_filter)

        self._parse_regex_list(
            sandbox_data.regex_count, sandbox_data.regex_table_offset
        )
        self._parse_global_vars(sandbox_data.vars_offset, sandbox_data.vars_count)
        self._parse_policies(
            sandbox_data.entitlements_offset, sandbox_data.entitlements_count
        )
        self._create_operation_nodes(
            sandbox_data.op_nodes_count, sandbox_data.operation_nodes_offset, filters, modifiers
        )
        self._parse_op_table(sandbox_data.sb_ops_count, sandbox_data.profiles_offset)

    def _read_sandbox_operations(self, path: str) -> None:
        with open(path, "r") as f:
            self.sb_ops = [line.strip() for line in f if line.strip()]
        logging.info(f"Read {len(self.sb_ops)} sandbox operations")

    def _filter_operations(self, ops: List[str]) -> None:
        missing = [op for op in ops if op not in self.sb_ops]
        if missing:
            logging.error(f"Invalid operations requested: {missing}")
            sys.exit(1)
        self.ops_to_reverse = ops
        logging.info(f"Filtered operations: {ops}")

    def _parse_regex_list(self, count: int, offset: int) -> None:
        if count == 0:
            return
        self.infile.seek(offset)
        offsets = struct.unpack(f"<{count}H", self.infile.read(2 * count))

        for off in offsets:
            self.infile.seek(self.base_addr + off * 8)
            length = struct.unpack("<H", self.infile.read(2))[0]
            data = self.infile.read(length)
            self.regex_list.append(regex.analyze(data))
        logging.info(f"Parsed {len(self.regex_list)} regex entries")

    def _parse_global_vars(self, offset: int, count: int) -> None:
        for i in range(count):
            self.infile.seek(offset + i * 2)
            var_offset = struct.unpack("<H", self.infile.read(2))[0]
            self.infile.seek(self.base_addr + var_offset * 8)
            strlen = struct.unpack("<H", self.infile.read(2))[0]
            string = self.infile.read(strlen - 1).decode("utf-8")
            self.global_vars.append(string)
        logging.info(f"Parsed global vars: {self.global_vars}")

    def _parse_policies(self, offset: int, count: int) -> None:
        self.infile.seek(offset)
        self.policies = struct.unpack(f"<{count}H", self.infile.read(2 * count))

    def _create_operation_nodes(self, count: int, offset: int, filters, modifiers) -> None:
        filter_resolver = FilterResolver(
            self.infile, self.base_addr, self.regex_list, self.global_vars, filters
        )
        modifier_resolver = ModifierResolver(
            self.infile, self.base_addr, self.regex_list, self.global_vars, modifiers
        )
        self.infile.seek(offset)
        parser = operation_node_parser.OperionNodeParser()
        parser.build_operation_nodes(
            self.infile, count, self, filter_resolver, modifier_resolver
        )
        self.operation_nodes = parser
        logging.info(f"Parsed {count} operation nodes")

    def _parse_op_table(self, count: int, offset: int) -> None:
        self.infile.seek(offset)
        self.op_table = struct.unpack(f"<{count}H", self.infile.read(2 * count))
