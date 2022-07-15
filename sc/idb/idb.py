# https://github.com/williballenthin/python-idb
# https://github.com/nlitsme/pyidbutil
# https://github.com/Vector35/idb-parser-rs
# https://github.com/aerosoul94/tilutil

from enum import Flag, IntFlag, auto
from struct import pack, unpack
from typing import BinaryIO, Optional, Sequence

from sc.idb.btree.idb import (
    Entry as IDBEntry,
    IndexEntry as IDBIndexEntry,
    LeafEntry as IDBLeafEntry,
    Page as IDBPage,
)
from sc.idb.btree.python import (
    Entry as PythonEntry,
    IndexEntry as PythonIndexEntry,
    IndexPage as PythonIndexPage,
    LeafEntry as PythonLeafEntry,
    LeafPage as PythonLeafPage,
    Page as PythonPage,
)

WORD_SIZES: dict[bytes, int] = {b"IDA0": 4, b"IDA1": 4, b"IDA2": 8}

WORD_FORMATS: dict[int, str] = {4: "I", 8: "Q"}


class SectionFlags(Flag):
    ID0 = auto()
    ID1 = auto()
    NAM = auto()
    SEG = auto()
    TIL = auto()
    ID2 = auto()
    ALL = ID0 | ID1 | NAM | SEG | TIL | ID2


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


def resolve_page(
    page_index: int, idb_pages: Sequence[IDBPage], python_pages: dict[int, PythonPage]
) -> PythonPage:
    if page_index in python_pages:
        return python_pages[page_index]

    idb_page: IDBPage = idb_pages[page_index - 1]

    idb_entry: IDBEntry
    python_page: PythonPage
    if idb_page.first_page_index:  # Index
        python_index_entries: list[PythonIndexEntry] = []
        last_page_index = idb_page.first_page_index
        for idb_entry in idb_page.entries:
            assert isinstance(idb_entry, IDBIndexEntry), "UNEXPECTED"

            python_index_entries.append(
                PythonIndexEntry(
                    idb_entry.key,
                    idb_entry.value,
                    resolve_page(last_page_index, idb_pages, python_pages),
                    resolve_page(idb_entry.page_index, idb_pages, python_pages),
                )
            )

            last_page_index = idb_entry.page_index

        python_page = PythonIndexPage(python_index_entries)
    else:  # Leaf
        python_leaf_entries: list[PythonLeafEntry] = []
        for idb_entry in idb_page.entries:
            assert isinstance(idb_entry, IDBLeafEntry), "UNEXPECTED"

            python_leaf_entries.append(PythonLeafEntry(idb_entry.key, idb_entry.value))

        python_page = PythonLeafPage(python_leaf_entries)

    python_pages[page_index] = python_page

    return python_page


class ID0(Section):
    word_size: int
    word_format: str
    next_free_offset: int
    page_size: int
    root_page_index: int
    record_count: int
    page_count: int
    magic: bytes
    root_page: PythonPage

    def __init__(self, file: BinaryIO, checksum: int, word_size: int) -> None:
        super().__init__(file, checksum)

        self.word_size = word_size

        self.word_format = WORD_FORMATS[self.word_size]

        (
            self.next_free_offset,
            self.page_size,
            self.root_page_index,
            self.record_count,
            self.page_count,
            self.magic,
        ) = unpack("<IHIIIx9s", file.read(28))

        assert self.magic == b"B-tree v2", "Bad IDA0 magic."

        file.seek(self.page_size - 28, 1)

        idb_pages: list[IDBPage] = []
        # The page count does not include dead entries.
        # TODO: Detect dead entries at this stage? Are they distinguished in any way?
        for _ in range((self.header.section_length // self.page_size) - 1):
            idb_pages.append(IDBPage(file.read(self.page_size)))

        self.root_page = resolve_page(self.root_page_index, idb_pages, {})

    def name(self, name: int) -> Optional[bytes]:
        key: bytes = pack(f">s{self.word_format}s", b".", name, b"N")

        entry: Optional[PythonEntry] = self.root_page.search(key, key, True, True)

        if entry is not None:
            return entry.value
        else:
            return None


class ID1Segment:
    start: int
    end: int
    data: bytes

    def __init__(self, start: int, end: int, data: bytes) -> None:
        assert (end - start) * 4 == len(data), "Bad ID1 segment data length."

        self.start = start
        self.end = end
        self.data = data


class ID1(Section):
    PAGE_SIZE: int = 0x2000

    word_size: int
    word_format: str
    magic: bytes
    segment_count: int
    page_count: int
    segments: list[ID1Segment]

    def __init__(self, file: BinaryIO, checksum: int, word_size: int) -> None:
        super().__init__(file, checksum)

        self.word_size = word_size

        self.word_format = WORD_FORMATS[self.word_size]

        (self.magic, self.segment_count, self.page_count) = unpack(
            "<4s4xI4xI", file.read(20)
        )

        assert self.magic == b"VA*\x00", "Invalid ID1 magic."

        start: int
        end: int
        segment_addresses: list[tuple[int, int]] = []
        for _ in range(self.segment_count):
            start, end = unpack(
                f"<{self.word_format}{self.word_format}",
                file.read(self.word_size * 2),
            )

            segment_addresses.append((start, end))

        file.seek(20 + (self.segment_count * self.word_size * 2), 1)

        self.segments = []
        for start, end in segment_addresses:
            self.segments.append(ID1Segment(start, end, file.read((end - start) * 4)))


class NAM(Section):
    PAGE_SIZE: int = 0x2000

    word_size: int
    word_format: str
    magic: bytes
    non_empty: int
    page_count: int
    name_count: int
    names: tuple[int, ...]

    def __init__(self, file: BinaryIO, checksum: int, word_size: int) -> None:
        super().__init__(file, checksum)

        self.word_size = word_size

        self.word_format = WORD_FORMATS[self.word_size]

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


class IDB:
    header: Header
    id0: Optional[ID0]
    id1: Optional[ID1]
    nam: Optional[NAM]
    seg: Optional[SEG]
    til: Optional[TIL]
    id2: Optional[ID2]

    def __init__(
        self, file: BinaryIO, sections: SectionFlags = SectionFlags.ALL
    ) -> None:
        self.header = Header(file)

        if self.header.id0_offset != 0 and sections & SectionFlags.ID0:
            file.seek(self.header.id0_offset)
            self.id0 = ID0(
                file, self.header.id0_checksum, WORD_SIZES[self.header.magic]
            )
        else:
            self.id0 = None

        if self.header.id1_offset != 0 and sections & SectionFlags.ID1:
            file.seek(self.header.id1_offset)
            self.id1 = ID1(
                file, self.header.id1_checksum, WORD_SIZES[self.header.magic]
            )
        else:
            self.id1 = None

        if self.header.nam_offset != 0 and sections & SectionFlags.NAM:
            file.seek(self.header.nam_offset)
            self.nam = NAM(
                file, self.header.nam_checksum, WORD_SIZES[self.header.magic]
            )
        else:
            self.nam = None

        if self.header.seg_offset != 0 and sections & SectionFlags.SEG:
            file.seek(self.header.seg_offset)
            self.seg = SEG(file, self.header.seg_checksum)
        else:
            self.seg = None

        if self.header.til_offset != 0 and sections & SectionFlags.TIL:
            file.seek(self.header.til_offset)
            self.til = TIL(file, self.header.til_checksum)
        else:
            self.til = None

        if self.header.id2_offset != 0 and sections & SectionFlags.ID2:
            file.seek(self.header.id2_offset)
            self.id2 = ID2(file, self.header.id2_checksum)
        else:
            self.id2 = None
