from dataclasses import dataclass, field
from typing import BinaryIO, List, Tuple, Optional
import struct

# ─── Low‑level constants ────────────────────────────────────────────────────────
INDEX_SIZE = 2
OPERATION_NODE_SIZE = 8
PROFILE_OPS_OFFSET = 4  # per‑profile fixed header

# ─── Helper functions (tiny, reusable) ─────────────────────────────────────────
def align_up(value: int, alignment: int = 8) -> int:
    """Return 'value' rounded up to the next multiple of 'alignment'."""
    mask = alignment - 1
    return (value + mask) & ~mask  # works for power‑of‑two alignments


# ─── Data model ────────────────────────────────────────────────────────────────
@dataclass(slots=True)
class SandboxData:
    # • Raw header fields (what the file actually stores) •
    header_size: int
    type: int
    op_nodes_count: int
    sb_ops_count: int
    vars_count: int
    regex_count: int
    states_count: int = 0
    num_profiles: int = 0
    entitlements_count: int = 0
    instructions_count: int = 0

    # • Parsed/decoded payloads (filled later by your own code) •
    op_table: int = field(default=None)
    regex_list: List[str] = field(default_factory=list)
    global_vars: List[str] = field(default_factory=list)
    policies: Optional[Tuple[int]] = None
    sb_ops: List[str] = field(default_factory=list)
    operation_nodes: Optional[List[object]] = None
    ops_to_reverse: List[str] = field(default_factory=list)

    # ── Offset & size properties (all read‑only) ───────────────────────────────
    @property
    def regex_table_offset(self) -> int:
        return self.header_size

    @property
    def vars_offset(self) -> int:
        return self.regex_table_offset + self.regex_count * INDEX_SIZE

    @property
    def states_offset(self) -> int:
        return self.vars_offset + self.vars_count * INDEX_SIZE

    @property
    def entitlements_offset(self) -> int:
        return self.states_offset + self.states_count * INDEX_SIZE

    @property
    def profiles_offset(self) -> int:
        return self.entitlements_offset + self.entitlements_count * INDEX_SIZE

    @property
    def profile_record_size(self) -> int:
        """Bytes consumed by *one* profile record in the profile table."""
        return self.sb_ops_count * INDEX_SIZE + PROFILE_OPS_OFFSET

    @property
    def profiles_end_offset(self) -> int:
        return self.profiles_offset + self.num_profiles * self.profile_record_size

    @property
    def operation_nodes_size(self) -> int:
        return self.op_nodes_count * OPERATION_NODE_SIZE

    @property
    def operation_nodes_offset(self) -> int:
        unaligned = self.profiles_end_offset + self.sb_ops_count * INDEX_SIZE
        return align_up(unaligned, 8)  # 8‑byte alignment

    @property
    def base_addr(self) -> int:
        """First byte *after* the operation‑node array – handy for builders."""
        return self.operation_nodes_offset + self.operation_nodes_size

    # ── Factory method ──────────────────────────────────────────────────────────
    @classmethod
    def from_file(cls, infile: BinaryIO) -> "SandboxData":
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
