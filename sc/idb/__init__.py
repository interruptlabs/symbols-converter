from argparse import Namespace

from sc.idb.extractors import (
    FunctionExtractor,
    FunctionExtractorFunction,
    SegmentExtractor,
    SegmentExtractorSegment,
)
from sc.idb.idb import IDB, SectionFlags as IDBSectionFlags
from sc.idb.net_node import NetNodeGenerator
from sc.structures import Bundle, Section, SectionFlags, Symbol, SymbolType


def from_idb(arguments: Namespace) -> Bundle:
    idb_ = IDB(
        file=arguments.idb.open("rb"),
        sections=IDBSectionFlags.ID0 | IDBSectionFlags.NAM,
        verify_checksum=arguments.verify_checksum,
    )

    assert idb_.id0 is not None, ".idb does not contain ID0 section."
    assert idb_.nam is not None, ".idb does not contain NAM section."

    bundle: Bundle = Bundle()

    bundle._64_bit = idb_.id0.word_size == 8

    net_node_generator: NetNodeGenerator = NetNodeGenerator(idb_.id0)

    segment_extractor: SegmentExtractor = SegmentExtractor(net_node_generator)

    flags: SectionFlags
    segment: SegmentExtractorSegment
    for segment in segment_extractor.segments:
        flags = SectionFlags(0)

        if segment.permissions & (1 << 0):
            flags |= SectionFlags.X

        if segment.permissions & (1 << 1):
            flags |= SectionFlags.W

        if segment.permissions & (1 << 2):
            flags |= SectionFlags.R

        # Unknown flags so make RWX.
        if flags == SectionFlags(0):
            flags = SectionFlags.R | SectionFlags.W | SectionFlags.X

        bundle.sections.append(Section(segment.name, segment.start, segment.end, flags))

    names = set(idb_.nam.names)

    function_extractor: FunctionExtractor = FunctionExtractor(net_node_generator)

    functions: dict[int, bytes] = {}
    function: FunctionExtractorFunction
    for function in function_extractor.functions:
        if function.name is not None:
            if not arguments.no_functions:
                functions[function.head_header.start] = function.name

            names.discard(function.head_header.start)
        elif arguments.auto_functions:
            functions[
                function.head_header.start
            ] = f"sub_{function.head_header.start:x}".encode()

    globals_: dict[int, bytes] = {}
    global_: int
    for global_ in names:
        if not arguments.no_globals:
            globals_[global_] = net_node_generator.net_node(global_).name()

    for address, name in functions.items():
        bundle.symbols.append(Symbol(name, address, SymbolType.FUNCTION))

    for address, name in globals_.items():
        bundle.symbols.append(Symbol(name, address, SymbolType.GLOBAL))

    return bundle
