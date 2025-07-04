from typing import BinaryIO
from construct import Struct, Int16ul, Int8ul, Padding

INDEX_SIZE = 2
OPERATION_NODE_SIZE = 8
PROFILE_OPS_OFFSET = 4
SANDBOX_HEADER_LAYOUT = Struct(
    "type" / Int16ul,
    "op_nodes_count" / Int16ul,
    "sb_ops_count" / Int8ul,
    "vars_count" / Int8ul,
    Padding(6),
    "regex_count" / Int16ul,
    "reserved" / Int16ul,
)


def align_up(value: int, alignment: int = 8) -> int:
    mask = alignment - 1
    return (value + mask) & ~mask


class SandboxHeader:
    header: None
    states_count: int = 0
    num_profiles: int = 0
    entitlements_count: int = 0

    def __init__(self, infile: BinaryIO):
        self.header = SANDBOX_HEADER_LAYOUT.parse_stream(infile)

    @property
    def regex_table_offset(self) -> int:
        return SANDBOX_HEADER_LAYOUT.sizeof()

    @property
    def vars_offset(self) -> int:
        return self.regex_table_offset + self.header.regex_count * INDEX_SIZE

    @property
    def states_offset(self) -> int:
        return self.vars_offset + self.header.vars_count * INDEX_SIZE

    @property
    def entitlements_offset(self) -> int:
        return self.states_offset + self.states_count * INDEX_SIZE

    @property
    def profiles_offset(self) -> int:
        return self.entitlements_offset + self.entitlements_count * INDEX_SIZE

    @property
    def profile_record_size(self) -> int:
        return self.header.sb_ops_count * INDEX_SIZE + PROFILE_OPS_OFFSET

    @property
    def profiles_end_offset(self) -> int:
        return self.profiles_offset + self.num_profiles * self.profile_record_size

    @property
    def operation_nodes_size(self) -> int:
        return self.header.op_nodes_count * OPERATION_NODE_SIZE

    @property
    def operation_nodes_offset(self) -> int:
        return align_up(
            self.profiles_end_offset + self.header.sb_ops_count * INDEX_SIZE
        )

    @property
    def base_addr(self) -> int:
        return self.operation_nodes_offset + self.operation_nodes_size
