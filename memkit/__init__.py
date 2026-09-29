"""memkit: a process memory toolkit for debugging and reverse engineering."""

from memkit.aob import Pattern, PatternError, scan_pattern
from memkit.dump import dump_region
from memkit.elf import ELFFile, ELFFormatError
from memkit.elf import parse as parse_elf
from memkit.elf import parse_file as parse_elf_file
from memkit.freeze import Freezer
from memkit.pe import PEFile, PEFormatError
from memkit.pe import parse as parse_pe
from memkit.pe import parse_file as parse_pe_file
from memkit.pointer import resolve
from memkit.process import (
    Process,
    UnsupportedPlatformError,
    find_processes,
    platform_name,
)
from memkit.ptrscan import Chain, scan_pointers
from memkit.regions import Region, list_regions
from memkit.scan import Scanner
from memkit.scripting import ScriptTarget, run_script, run_script_file
from memkit.session import ScanRecord, Session, Snapshot, take_snapshot
from memkit.strings import StringHit, find_strings, scan_strings
from memkit.structs import BytesReader, Field, ProcessReader, Struct, Union
from memkit.structs import parse_c as parse_c_structs
from memkit.tui import HexViewer
from memkit.types import TYPES, pack, unpack

__version__ = "0.1.0"
__all__ = [
    "TYPES",
    "pack",
    "unpack",
    "Process",
    "UnsupportedPlatformError",
    "find_processes",
    "platform_name",
    "Region",
    "list_regions",
    "Scanner",
    "resolve",
    "Freezer",
    "dump_region",
    "Pattern",
    "PatternError",
    "scan_pattern",
    "ELFFile",
    "ELFFormatError",
    "parse_elf",
    "parse_elf_file",
    "PEFile",
    "PEFormatError",
    "parse_pe",
    "parse_pe_file",
    "Chain",
    "scan_pointers",
    "StringHit",
    "find_strings",
    "scan_strings",
    "Struct",
    "Union",
    "Field",
    "BytesReader",
    "ProcessReader",
    "parse_c_structs",
    "Session",
    "ScanRecord",
    "Snapshot",
    "take_snapshot",
    "ScriptTarget",
    "run_script",
    "run_script_file",
    "HexViewer",
    "__version__",
]
