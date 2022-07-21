from typing import Optional

from sc.idb.btree.python import Entry
from sc.idb.net_node import NetNode, NetNodeGenerator


class Extractor:
    def __init__(self, net_node_generator: NetNodeGenerator) -> None:
        pass


class SegmentExtractorSegment:
    start: int
    end: int
    name_index: int
    name: bytes
    class_: int
    org_base: int
    flags: int
    alignment_codes: int
    combination_codes: int
    permissions: int
    bitness: int
    type: int
    selector: int
    colour: int

    def __init__(
        self, entry: Entry, net_node: NetNode, segment_strings: list[bytes]
    ) -> None:
        (
            self.start,
            self.end,
            self.name_index,
            self.class_,
            self.org_base,
            self.flags,
            self.alignment_codes,
            self.combination_codes,
            self.permissions,
            self.bitness,
            self.type,
            self.selector,
            self.colour,
        ) = net_node.unpack("WWWWWUUUUUUUU", entry.value)

        assert self.start == net_node.key_index(
            entry.key
        ), "Segment start and index mismatch."

        self.end += self.start

        self.name = segment_strings[self.name_index]

        # TODO: Properly parse class.

        assert 0 <= self.bitness <= 2, "Bad segment bitness."

        self.bitness = 1 << (self.bitness + 4)

        self.colour -= 1
        self.colour &= 0xFFFFFFFF


class SegmentExtractor(Extractor):
    segments: list[SegmentExtractorSegment]

    def __init__(self, net_node_generator: NetNodeGenerator) -> None:
        super().__init__(net_node_generator)

        segment_strings_: bytes = (
            net_node_generator.net_node(b"$ segstrings").entry(b"S", 0).value
        )

        segment_strings: list[bytes] = []
        offset: int = 0
        length: int
        while offset < len(segment_strings_):
            length = segment_strings_[offset]
            offset += 1
            segment_strings.append(segment_strings_[offset : offset + length])
            offset += length

        segments_net_node: NetNode = net_node_generator.net_node(b"$ segs")

        self.segments = []
        entry: Entry
        for entry in segments_net_node.entries(b"S"):
            self.segments.append(
                SegmentExtractorSegment(entry, segments_net_node, segment_strings)
            )


class FunctionExtractorChunkHeader:
    TAIL: int = 0b1000000000000000

    start: int
    end: int
    flags: int
    frame: Optional[int]
    locals_size: Optional[int]
    registers_size: Optional[int]
    arguments_size: Optional[int]
    parent: Optional[int]
    referer_count: Optional[int]

    def __init__(self, entry: Entry, net_node: NetNode) -> None:
        offset: int

        self.start, self.end, self.flags, offset = net_node.unpack(
            "WWT", entry.value, return_offset=True
        )

        assert self.start == net_node.key_index(
            entry.key
        ), "Function start and index mismatch."

        self.end += self.start

        if self.flags & FunctionExtractorChunkHeader.TAIL:
            self.parent, self.referer_count = net_node.unpack(
                "wU", entry.value[offset:]
            )

            assert self.parent is not None, "UNEXPECTED"

            self.parent = self.start - self.parent

            self.frame = None
            self.locals_size = None
            self.registers_size = None
            self.arguments_size = None
        else:
            (
                self.frame,
                self.locals_size,
                self.registers_size,
                self.arguments_size,
            ) = net_node.unpack("WWTW", entry.value[offset:])

            self.parent = None
            self.referer_count = None


class FunctionExtractorFunction:
    head_header: FunctionExtractorChunkHeader
    tail_headers: list[FunctionExtractorChunkHeader]
    name: Optional[bytes]

    def __init__(
        self,
        net_nodes_generator: NetNodeGenerator,
        headers: list[FunctionExtractorChunkHeader],
    ) -> None:
        head_header: Optional[FunctionExtractorChunkHeader] = None
        self.tail_headers = []
        header: FunctionExtractorChunkHeader
        for header in headers:
            if header.flags & FunctionExtractorChunkHeader.TAIL:
                self.tail_headers.append(header)
            else:
                if head_header is None:
                    head_header = header
                else:
                    assert False, "Duplicate head headers."

        assert head_header is not None, "No head header."

        self.head_header = head_header

        try:
            self.name = net_nodes_generator.net_node(self.head_header.start).name()
        except KeyError:
            self.name = None


class FunctionExtractor(Extractor):
    functions: list[FunctionExtractorFunction]

    def __init__(self, net_node_generator: NetNodeGenerator) -> None:
        super().__init__(net_node_generator)

        function_header_net_node = net_node_generator.net_node(b"$ funcs")

        chunk_header_groups: dict[int, list[FunctionExtractorChunkHeader]] = {}
        key: int
        chunk_header: FunctionExtractorChunkHeader
        entry: Entry
        for entry in function_header_net_node.entries(b"S"):
            chunk_header = FunctionExtractorChunkHeader(entry, function_header_net_node)

            key = chunk_header.parent or chunk_header.start

            if key in chunk_header_groups:
                chunk_header_groups[key].append(chunk_header)
            else:
                chunk_header_groups[key] = [chunk_header]

        self.functions = []
        chunk_header_group: list[FunctionExtractorChunkHeader]
        for chunk_header_group in chunk_header_groups.values():
            self.functions.append(
                FunctionExtractorFunction(
                    net_node_generator,
                    chunk_header_group,
                )
            )
