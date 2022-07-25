from argparse import Namespace
from typing import BinaryIO

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
from sc.structures import Bundle, Section, SectionFlags, Symbol, SymbolType
from sc.util import fnn

# https://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/specialsections.html
SECTION_TYPES: dict[bytes, SHType] = {  # Types
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


def to_sym(arguments: Namespace, bundle: Bundle) -> None:
    elf_: ELF = ELF(undefined_section=True)

    flags: SHFlags
    section: Section
    for section in bundle.sections:
        flags = SECTION_FLAGS.get(section.name, SHFlags.SHF_ALLOC)

        if section.flags & SectionFlags.W:
            flags |= SHFlags.SHF_WRITE

        if section.flags & SectionFlags.X:
            flags |= SHFlags.SHF_EXECINSTR

        elf_.sections.append(
            BytesSection(
                name=section.name,
                type_=SECTION_TYPES.get(section.name, SHType.SHT_PROGBITS),
                flags=flags,
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

    elf_.sections.append(symbol_table)

    sym_file: BinaryIO
    with arguments.sym.open("wb") as sym_file:
        sym_file.write(
            elf_.to_bytes(
                fnn(arguments._64_bit, bundle._64_bit, True),
                fnn(arguments.big_endian, bundle.big_endian, True),
                abi=fnn(arguments.abi, EIOSABI.ELFOSABI_NONE),
                abi_version=fnn(arguments.abi_version, 0),
                type_=fnn(arguments.type, EType.ET_NONE),
                machine=fnn(arguments.machine, EMachine.EM_NONE),
                entry_pont=fnn(arguments.entry_point, 0),
                flags=fnn(arguments.flags, 0),
            )
        )
