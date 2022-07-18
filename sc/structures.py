from enum import Enum, auto, Flag
from typing import Optional


class SectionFlags(Flag):
    R = auto()
    W = auto()
    X = auto()


class Section:
    name: bytes
    start: int
    end: int
    flags: SectionFlags

    def __init__(self, name: bytes, start: int, end: int, flags: SectionFlags) -> None:
        self.name = name
        self.start = start
        self.end = end
        self.flags = flags


class SymbolType(Enum):
    FUNCTION = auto()
    GLOBAL = auto()


class Symbol:
    name: bytes
    address: int
    type: SymbolType

    def __init__(self, name: bytes, address: int, type_: SymbolType) -> None:
        self.name = name
        self.address = address
        self.type = type_


class Bundle:
    _64_bit: Optional[bool]
    big_endian: Optional[bool]
    sections: list[Section]
    symbols: list[Symbol]

    def __init__(self) -> None:
        self._64_bit = None
        self.big_endian = None
        self.sections = []
        self.symbols = []
