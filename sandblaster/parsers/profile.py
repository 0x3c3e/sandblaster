from dataclasses import dataclass, field
from typing import BinaryIO, List, Optional, Tuple


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
