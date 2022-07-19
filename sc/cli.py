from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import BinaryIO, Optional

from sc.elf.constants import (
    EIOSABI,
    EMachine,
    EType,
    SHFlags,
    SHType,
    STBind,
    STType,
    STVisibility,
)
from sc.elf.elf import BytesSection, ELF, SymbolTableEntry, SymbolTableSection
from sc.idb.extractors import (
    FunctionExtractor,
    FunctionExtractorFunction,
    SegmentExtractor,
    SegmentExtractorSegment,
)
from sc.idb.idb import IDB, SectionFlags as IDBSectionFlags
from sc.idb.net_node import NetNodeGenerator
from sc.structures import Bundle, Section, SectionFlags, Symbol, SymbolType

# https://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/specialsections.html
SECTION_TYPES: dict[bytes, SHType] = {
    b".bss": SHType.SHT_NOBITS,
    b".comment": SHType.SHT_PROGBITS,
    b".data": SHType.SHT_PROGBITS,
    b".data1": SHType.SHT_PROGBITS,
    b".debug": SHType.SHT_PROGBITS,
    b".dynamic": SHType.SHT_DYNAMIC,
    b".dynstr": SHType.SHT_STRTAB,
    b".dynsym": SHType.SHT_DYNSYM,
    b".fini": SHType.SHT_PROGBITS,
    b".fini_array": SHType.SHT_FINI_ARRAY,
    b".hash": SHType.SHT_HASH,
    b".init": SHType.SHT_PROGBITS,
    b".init_array": SHType.SHT_INIT_ARRAY,
    b".interp": SHType.SHT_PROGBITS,
    b".line": SHType.SHT_PROGBITS,
    b".note": SHType.SHT_NOTE,
    b".preinit_array": SHType.SHT_PREINIT_ARRAY,
    b".rodata": SHType.SHT_PROGBITS,
    b".rodata1": SHType.SHT_PROGBITS,
    b".shstrtab": SHType.SHT_STRTAB,
    b".strtab": SHType.SHT_STRTAB,
    b".symtab": SHType.SHT_SYMTAB,
    b".tbss": SHType.SHT_NOBITS,
    b".tdata": SHType.SHT_PROGBITS,
    b".text": SHType.SHT_PROGBITS,
}

# https://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/specialsections.html
SECTION_FLAGS: dict[bytes, SHFlags] = {
    b".bss": SHFlags.SHF_ALLOC,
    b".comment": SHFlags(0),
    b".data": SHFlags.SHF_ALLOC,
    b".data1": SHFlags.SHF_ALLOC,
    b".debug": SHFlags(0),
    b".dynamic": SHFlags.SHF_ALLOC,
    b".dynstr": SHFlags.SHF_ALLOC,
    b".dynsym": SHFlags.SHF_ALLOC,
    b".fini": SHFlags.SHF_ALLOC,
    b".fini_array": SHFlags.SHF_ALLOC,
    b".hash": SHFlags.SHF_ALLOC,
    b".init": SHFlags.SHF_ALLOC,
    b".init_array": SHFlags.SHF_ALLOC,
    b".interp": SHFlags.SHF_ALLOC,
    b".line": SHFlags(0),
    b".note": SHFlags(0),
    b".preinit_array": SHFlags.SHF_ALLOC,
    b".rodata": SHFlags.SHF_ALLOC,
    b".rodata1": SHFlags.SHF_ALLOC,
    b".shstrtab": SHFlags(0),
    b".strtab": SHFlags.SHF_ALLOC,
    b".symtab": SHFlags.SHF_ALLOC,
    b".tbss": SHFlags.SHF_ALLOC | SHFlags.SHF_TLS,
    b".tdata": SHFlags.SHF_ALLOC | SHFlags.SHF_TLS,
    b".text": SHFlags.SHF_ALLOC,
}

SYMBOL_TYPES: dict[SymbolType, STType] = {
    SymbolType.FUNCTION: STType.STT_FUNC,
    SymbolType.GLOBAL: STType.STT_OBJECT,
}


def resolved_file(string: str) -> Path:
    path: Path = Path(string).resolve()

    assert path.is_file(), "Path must be a file."

    return path


def resolved_nonexistent(string: str) -> Path:
    path: Path = Path(string).resolve()

    assert not path.exists(), "Path must not exist."

    return path


def parse_arguments() -> Namespace:
    parser: ArgumentParser = ArgumentParser(
        description="Converts an .idb file to a .sym (ELF) file."
    )

    parser.add_argument(
        "-i",
        "--idb",
        type=resolved_file,
        required=True,
        help="Path of the .idb file (input).",
        metavar="PATH",
    )

    parser.add_argument(
        "-s",
        "--sym",
        type=resolved_nonexistent,
        required=True,
        help="Path of the .sym file (output).",
        metavar="PATH",
    )

    parser.add_argument(
        "-f",
        "--no-functions",
        action="store_true",
        help="Do not include functions in the output.",
    )

    parser.add_argument(
        "-F",
        "--auto-functions",
        action="store_true",
        help="Include automatically named functions in the output.",
    )

    parser.add_argument(
        "-g",
        "--no-globals",
        action="store_true",
        help="Do not include globals in the output.",
    )

    parser.add_argument(
        "-w",
        "--word-size",
        choices=("32", "64"),
        help="The word size of the binary. Defaults to trying to extract from the input file and then 64 bit.",
    )

    parser.add_argument(
        "-e",
        "--endianness",
        choices=("little", "big"),
        help="The endianness of the binary. Defaults to trying to extract from the input file and then big endian.",
    )

    parser.add_argument(
        "--abi", choices=tuple(i.name[9:] for i in EIOSABI), help="Defaults to NONE"
    )

    parser.add_argument("--abi-version", type=int, help="Defaults to 0.")

    parser.add_argument(
        "--type", choices=tuple(i.name[3:] for i in EType), help="Defaults to NONE."
    )

    parser.add_argument(
        "--machine",
        choices=tuple(i.name[3:] for i in EMachine),
        help="Defaults to NONE.",
    )

    parser.add_argument("--entry-point", type=int, help="Defaults to 0.")

    parser.add_argument("--flags", type=int, help="Defaults to 0.")

    arguments: Namespace = parser.parse_args()

    if arguments.word_size is None:
        arguments._64_bit = None
    else:
        arguments._64_bit = arguments.word_size == "64"

    if arguments.endianness is None:
        arguments.big_endian = None
    else:
        arguments.big_endian = arguments.endianness == "big"

    if arguments.abi is not None:
        arguments.abi = EIOSABI[f"ELFOSABI_{arguments.abi}"]

    if arguments.type is not None:
        arguments.type = EType[f"ET_{arguments.type}"]

    if arguments.machine is not None:
        arguments.machine = EMachine[f"EM_{arguments.machine}"]

    return arguments


def from_idb(arguments: Namespace) -> Bundle:
    idb = IDB(
        file=arguments.idb.open("rb"),
        sections=IDBSectionFlags.ID0 | IDBSectionFlags.ID1 | IDBSectionFlags.NAM,
    )

    assert idb.id0 is not None, ".idb does not contain ID0 section."
    assert idb.id1 is not None, ".idb does not contain ID1 section."
    assert idb.nam is not None, ".idb does not contain NAM section."

    bundle: Bundle = Bundle()

    bundle._64_bit = idb.id0.word_size == 8

    net_node_generator: NetNodeGenerator = NetNodeGenerator(idb.id0)

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

    names = set(idb.nam.names)

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


def main() -> None:
    arguments: Namespace = parse_arguments()

    bundle: Bundle = from_idb(arguments)

    elf: ELF = ELF(undefined_section=True)

    section: Section
    for section in bundle.sections:
        elf.sections.append(
            BytesSection(
                name=section.name,
                type_=SECTION_TYPES.get(section.name, SHType.SHT_PROGBITS),
                flags=SECTION_FLAGS.get(section.name, SHFlags.SHF_ALLOC)
                | (SHFlags.SHF_WRITE if section.flags | SectionFlags.W else 0)
                | (SHFlags.SHF_EXECINSTR if section.flags | SectionFlags.X else 0),
                address=section.start,
                link=0,
                info=0,
                alignment=1,
                entry_size=0,
                data=b"",
            )
        )

    symbol_table: SymbolTableSection = SymbolTableSection(
        name=b".symtab",
        type_=SHType.SHT_SYMTAB,
        flags=SHFlags.SHF_ALLOC,
        address=0,
        link=0,
        info=0,
        alignment=1,
        entry_size=0,
    )

    section_index: int
    symbol: Symbol
    for symbol in bundle.symbols:
        for section_index, section in enumerate(bundle.sections):
            if section.start <= symbol.address < section.end:
                break
        else:
            continue

        symbol_table.entries.append(
            SymbolTableEntry(
                name=symbol.name,
                binding=STBind.STB_LOCAL,
                type_=SYMBOL_TYPES[symbol.type],
                visibility=STVisibility.STV_DEFAULT,
                section_index=section_index + 1,
                value=symbol.address,
                size=0,
            )
        )

    elf.sections.append(symbol_table)

    sym_file: BinaryIO
    with arguments.sym.open("wb") as sym_file:
        sym_file.write(
            elf.to_bytes(
                next(
                    i
                    for i in (arguments._64_bit, bundle._64_bit, True)
                    if i is not None
                ),
                next(
                    i
                    for i in (arguments.big_endian, bundle.big_endian, True)
                    if i is not None
                ),
                abi=arguments.abi or EIOSABI.ELFOSABI_NONE,
                abi_version=arguments.abi_version or 0,
                type_=arguments.type or EType.ET_NONE,
                machine=arguments.machine or EMachine.EM_NONE,
                entry_pont=arguments.entry_point or 0,
                flags=arguments.flags or 0,
            )
        )


if __name__ == "__main__":
    main()
