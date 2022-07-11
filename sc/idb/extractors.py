from struct import unpack

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
        ) = net_node.unpack("*****UUUUUUUU", entry.value)

        assert self.start == net_node.key_index(
            entry.key
        ), "Segment start and index mismatch."

        self.end += self.start

        self.name = segment_strings[self.name_index]

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

        entry: Entry
        self.segments = []
        for entry in segments_net_node.entries(b"S"):
            self.segments.append(
                SegmentExtractorSegment(entry, segments_net_node, segment_strings)
            )
