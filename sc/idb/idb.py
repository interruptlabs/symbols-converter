# https://github.com/williballenthin/python-idb
# https://github.com/nlitsme/pyidbutil
# https://github.com/Vector35/idb-parser-rs
# https://github.com/aerosoul94/tilutil

from enum import IntFlag
from struct import unpack
from typing import BinaryIO, Optional

from sc.idb.btree import Page


class Header:
    magic: bytes
    id0_offset: int
    id1_offset: int
    signature: int
    version: int
    nam_offset: int
    seg_offset: int
    til_offset: int
    id0_checksum: int
    id1_checksum: int
    nam_checksum: int
    seg_checksum: int
    til_checksum: int
    id2_offset: int
    id2_checksum: int

    def __init__(self, file: BinaryIO) -> None:
        (
            self.magic,
            self.id0_offset,
            self.id1_offset,
            self.signature,
            self.version,
            self.nam_offset,
            self.seg_offset,
            self.til_offset,
            self.id0_checksum,
            self.id1_checksum,
            self.nam_checksum,
            self.seg_checksum,
            self.til_checksum,
            self.id2_offset,
            self.id2_checksum,
        ) = unpack("<4s2xQQ4xIHQQQIIIIIQI", file.read(88))

        assert self.magic in (b"IDA0", b"IDA1", b"IDA2"), "Bad magic."
        assert self.signature == 0xAABBCCDD, "Bad signature."
        assert self.version == 6, "Unsupported version."


class SectionHeader:
    compression_method: int
    section_length: int

    def __init__(self, file: BinaryIO) -> None:
        self.compression_method, self.section_length = unpack("<BQ", file.read(9))


class Section:
    header: SectionHeader
    checksum: int

    def __init__(self, file: BinaryIO, checksum: int):
        self.header = SectionHeader(file)
        self.checksum = checksum

        # TODO: Support decompression.
        # TODO: Checksum verification.


class ID0(Section):
    word_size: int
    word_format: str
    next_free_offset: int
    page_size: int
    root_page: int
    record_count: int
    page_count: int
    magic: bytes
    pages: list[Page]

    def __init__(self, file: BinaryIO, checksum: int, word_size: int) -> None:
        super().__init__(file, checksum)
        print(type(self).__name__)

        self.word_size = word_size

        assert self.word_size in (4, 8), "Bad ID0 word size."

        self.word_format = {4: "I", 8: "Q"}[self.word_size]

        (
            self.next_free_offset,
            self.page_size,
            self.root_page,
            self.record_count,
            self.page_count,
            self.magic,
        ) = unpack("<IHIIIx9s", file.read(28))

        assert self.magic == b"B-tree v2", "Bad IDA0 magic."

        file.seek(self.page_size - 28, 1)

        self.pages = []
        for _ in range(self.page_count - 1):
            self.pages.append(Page(file.read(self.page_size)))


class ID1(Section):
    def __init__(self, file: BinaryIO, checksum: int) -> None:
        super().__init__(file, checksum)
        print(type(self).__name__)


class NAM(Section):
    PAGE_SIZE = 0x2000

    word_size: int
    word_format: str
    magic: bytes
    non_empty: int
    page_count: int
    name_count: int
    names: tuple[int, ...]

    def __init__(self, file: BinaryIO, checksum: int, word_size: int) -> None:
        super().__init__(file, checksum)
        print(type(self).__name__)

        self.word_size = word_size

        assert self.word_size in (4, 8), "Bad NAM word size."

        self.word_format = {4: "I", 8: "Q"}[self.word_size]

        (self.magic, self.non_empty, self.page_count, self.name_count) = unpack(
            f"<4s4xI4xI{self.word_size}xI", file.read(24 + self.word_size)
        )

        assert self.magic == b"VA*\x00", "Bad NAM magic."

        if self.word_size == 8:
            self.name_count //= 2

        # The actual contents start at page index 1.
        file.seek(NAM.PAGE_SIZE - (24 + self.word_size), 1)

        self.names = unpack(
            f"<{self.name_count}{self.word_format}",
            file.read(self.name_count * self.word_size),
        )


class SEG(Section):
    def __init__(self, file: BinaryIO, checksum: int) -> None:
        super().__init__(file, checksum)
        print(type(self).__name__)


class TILFlags(IntFlag):
    ZIP: int = 0x0001
    MAC: int = 0x0002
    ESI: int = 0x0004
    UNI: int = 0x0008
    ORD: int = 0x0010
    ALI: int = 0x0020
    MOD: int = 0x0040
    STM: int = 0x0080
    SLD: int = 0x0100


class TIL(Section):
    magic: bytes
    format: int
    flags: TILFlags
    title_length: int
    title: bytes
    base_length: int
    base: bytes
    id: int
    cm: int
    size_i: int
    size_b: int
    size_e: int
    def_align: int

    def __init__(self, file: BinaryIO, checksum: int) -> None:
        super().__init__(file, checksum)
        print(type(self).__name__)

        flags: int
        (
            self.magic,
            self.format,
            flags,
            self.title_length,
        ) = unpack("<6sIIB", file.read(15))
        self.flags = TILFlags(flags)

        assert self.magic == b"IDATIL", "Bad TIL magic."

        self.title = file.read(self.title_length)

        (self.base_length,) = unpack("<B", file.read(1))

        self.base = file.read(self.base_length)

        (
            self.id,
            self.cm,
            self.size_i,
            self.size_b,
            self.size_e,
            self.def_align,
        ) = unpack("<BBBBBB", file.read(6))

        # TODO: TIL parsing.


class ID2(Section):
    def __init__(self, file: BinaryIO, checksum: int) -> None:
        super().__init__(file, checksum)
        print(type(self).__name__)


class IDB:
    header: Header
    id0: Optional[ID0]
    id1: Optional[ID1]
    nam: Optional[NAM]
    seg: Optional[SEG]
    til: Optional[TIL]
    id2: Optional[ID2]

    def __init__(self, file: BinaryIO) -> None:
        self.header = Header(file)

        if self.header.id0_offset != 0:
            file.seek(self.header.id0_offset)
            self.id0 = ID0(
                file, self.header.id0_checksum, 8 if self.header.magic == b"IDA2" else 4
            )
        else:
            self.id0 = None

        if self.header.id1_offset != 0:
            file.seek(self.header.id1_offset)
            self.id1 = ID1(file, self.header.id1_checksum)
        else:
            self.id1 = None

        if self.header.nam_offset != 0:
            file.seek(self.header.nam_offset)
            self.nam = NAM(
                file, self.header.nam_checksum, 8 if self.header.magic == b"IDA2" else 4
            )
        else:
            self.nam = None

        if self.header.seg_offset != 0:
            file.seek(self.header.seg_offset)
            self.seg = SEG(file, self.header.seg_checksum)
        else:
            self.seg = None

        if self.header.til_offset != 0:
            file.seek(self.header.til_offset)
            self.til = TIL(file, self.header.til_checksum)
        else:
            self.til = None

        if self.header.id2_offset != 0:
            file.seek(self.header.id2_offset)
            self.id2 = ID2(file, self.header.id2_checksum)
        else:
            self.id2 = None


if __name__ == "__main__":
    i = IDB(
        open(
            "../../vxworks/tp-link_TL-WR543G_firmware_ida_databases/wr543gv1_070809.idb",
            "rb",
        )
    )
