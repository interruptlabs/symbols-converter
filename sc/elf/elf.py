# https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html

from struct import pack, unpack
from typing import BinaryIO, Optional

from sc.elf.constants import *


class ELFHeader:
    e_ident_ei_mag: bytes
    e_ident_ei_class: EIClass
    e_ident_ei_data: EIData
    e_ident_ei_version: EIVersion
    e_ident_ei_osabi: EIOSABI
    e_ident_ei_abiversion: int
    e_ident_ei_pad: bytes
    e_type: EType
    e_machine: EMachine
    e_version: EVersion
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    def __init__(self, file: Optional[BinaryIO] = None) -> None:
        if file is not None:
            self._init_file(file)
        else:
            raise TypeError("Invalid combination of arguments.")

    @property
    def word_size(self) -> int:
        return {EIClass.ELFCLASS32: 4, EIClass.ELFCLASS64: 8}[self.e_ident_ei_class]

    @property
    def word_format(self) -> str:
        return {EIClass.ELFCLASS32: "I", EIClass.ELFCLASS64: "Q"}[self.e_ident_ei_class]

    @property
    def endian_format(self) -> str:
        return {EIData.ELFDATA2LSB: "<", EIData.ELFDATA2MSB: ">"}[self.e_ident_ei_data]

    def _init_file(self, file: BinaryIO) -> None:
        e_ident_ei_class: int
        e_ident_ei_data: int
        e_ident_ei_version: int
        e_ident_ei_osabi: int
        (
            self.e_ident_ei_mag,
            e_ident_ei_class,
            e_ident_ei_data,
            e_ident_ei_version,
            e_ident_ei_osabi,
            self.e_ident_ei_abiversion,
            self.e_ident_ei_pad,
        ) = unpack("<4sBBBBB7s", file.read(16))

        assert self.e_ident_ei_mag == b"\x7fELF", "Bad ELF magic."

        self.e_ident_ei_class = EIClass(e_ident_ei_class)
        self.e_ident_ei_data = EIData(e_ident_ei_data)
        self.e_ident_ei_version = EIVersion(e_ident_ei_version)
        self.e_ident_ei_osabi = EIOSABI(e_ident_ei_osabi)

        e_type: int
        e_machine: int
        e_version: int
        (
            e_type,
            e_machine,
            e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = unpack(
            f"{self.endian_format}HHI{self.word_format}{self.word_format}{self.word_format}IHHHHHH",
            file.read(24 + (3 * self.word_size)),
        )

        self.e_type = EType(e_type)
        self.e_machine = EMachine(e_machine)
        self.e_version = EVersion(e_version)

    def to_bytes(self) -> bytes:
        return pack(
            f"{self.endian_format}4sBBBBB7sHHI{self.word_format}{self.word_format}{self.word_format}IHHHHHH",
            self.e_ident_ei_mag,
            self.e_ident_ei_class,
            self.e_ident_ei_data,
            self.e_ident_ei_version,
            self.e_ident_ei_osabi,
            self.e_ident_ei_abiversion,
            self.e_ident_ei_pad,
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        )


class ProgramHeader:
    p_type: PType
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    def __init__(
        self, file: Optional[BinaryIO] = None, elf_header: Optional[ELFHeader] = None
    ) -> None:
        if file is not None and elf_header is not None:
            self._init_file(file, elf_header)
        else:
            raise TypeError("Invalid combination of arguments.")

    def _init_file(self, file: BinaryIO, elf_header: ELFHeader) -> None:
        assert elf_header.e_phentsize == 8 + (
            6 * elf_header.word_size
        ), "Program header size mismatch."

        p_type: int
        (p_type,) = unpack(f"{elf_header.endian_format}I", file.read(4))

        self.p_type = PType(p_type)

        if elf_header.word_size == 8:
            (self.p_flags,) = unpack(f"{elf_header.endian_format}I", file.read(4))

        self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz, self.p_memsz = unpack(
            f"{elf_header.endian_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}",
            file.read(5 * elf_header.word_size),
        )

        if elf_header.word_size == 4:
            (self.p_flags,) = unpack(f"{elf_header.endian_format}I", file.read(4))

        (self.p_align,) = unpack(
            f"{elf_header.endian_format}{elf_header.word_format}",
            file.read(elf_header.word_size),
        )

    def to_bytes(self, word_size: int, word_format: int, endian_format: int) -> bytes:
        result: bytearray = bytearray()

        result += pack(f"{endian_format}I", self.p_type)

        if word_size == 8:
            result += pack(f"{endian_format}I", self.p_flags)

        result += pack(
            f"{endian_format}{word_format}{word_format}{word_format}{word_format}{word_format}",
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
        )

        if word_size == 4:
            result += pack(f"{endian_format}I", self.p_flags)

        result += pack(f"{endian_format}{word_format}", self.p_align)

        return bytes(result)


class SectionHeader:
    sh_name: int
    sh_type: SHType
    sh_flags: SHFlags
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int

    def __init__(
        self, file: Optional[BinaryIO] = None, elf_header: Optional[ELFHeader] = None
    ) -> None:
        if file is not None and elf_header is not None:
            self._init_file(file, elf_header)
        else:
            raise TypeError("Invalid combination of arguments.")

    def _init_file(self, file: BinaryIO, elf_header: ELFHeader) -> None:
        assert elf_header.e_shentsize == 16 + (
            6 * elf_header.word_size
        ), "Section header size mismatch."

        sh_type: int
        sh_flags: int
        (
            self.sh_name,
            sh_type,
            sh_flags,
            self.sh_addr,
            self.sh_offset,
            self.sh_size,
            self.sh_link,
            self.sh_info,
            self.sh_addralign,
            self.sh_entsize,
        ) = unpack(
            f"{elf_header.endian_format}II{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}II{elf_header.word_format}{elf_header.word_format}",
            file.read(16 + (6 * elf_header.word_size)),
        )

        self.sh_type = SHType(sh_type)
        self.sh_flags = SHFlags(sh_flags)

        assert (
            self.sh_addralign & (self.sh_addralign - 1) == 0
        ), "Section alignment not a power of two."

        assert (self.sh_addralign == 0) or (
            self.sh_addr % self.sh_addralign == 0
        ), "Section address not aligned."

    def to_bytes(self, word_size: int, word_format: int, endian_format: int) -> bytes:
        return pack(
            f"{endian_format}II{word_format}{word_format}{word_format}{word_format}II{word_format}{word_format}",
            self.sh_name,
            self.sh_type,
            self.sh_flags,
            self.sh_addr,
            self.sh_offset,
            self.sh_size,
            self.sh_link,
            self.sh_info,
            self.sh_addralign,
            self.sh_entsize,
        )


class Section:
    name: bytes
    type: SHType
    flags: SHFlags
    address: int
    link: int
    info: int
    alignment: int
    entry_size: int

    def __init__(
        self,
        name: bytes,
        type_: SHType,
        flags: SHFlags,
        address: int,
        link: int,
        info: int,
        alignment: int,
        entry_size: int,
    ) -> None:
        self.name = name
        self.type = type_
        self.flags = flags
        self.address = address
        self.link = link
        self.info = info
        self.alignment = alignment
        self.entry_size = entry_size


class BytesSection(Section):
    data: bytes

    def __init__(
        self,
        file: Optional[BinaryIO] = None,
        header: Optional[SectionHeader] = None,
        name: Optional[bytes] = None,
    ) -> None:
        if file is not None and header is not None and name is not None:
            super().__init__(
                name,
                header.sh_type,
                header.sh_flags,
                header.sh_addr,
                header.sh_link,
                header.sh_info,
                header.sh_addralign,
                header.sh_entsize,
            )
            self._init_file(file, header)
        else:
            raise TypeError("Invalid combination of arguments.")

    def _init_file(self, file: BinaryIO, header: SectionHeader) -> None:
        file.seek(header.sh_offset, 0)

        self.data = file.read(header.sh_size)

    def to_bytes(self) -> bytes:
        return self.data


class StringTableSection(Section):
    data: bytearray

    def __init__(
        self,
        file: Optional[BinaryIO] = None,
        header: Optional[SectionHeader] = None,
        name: Optional[bytes] = None,
    ) -> None:
        if file is not None and header is not None and name is not None:
            super().__init__(
                name,
                header.sh_type,
                header.sh_flags,
                header.sh_addr,
                header.sh_link,
                header.sh_info,
                header.sh_addralign,
                header.sh_entsize,
            )
            self._init_file(file, header)
        else:
            raise TypeError("Invalid combination of arguments.")

    def _init_file(self, file: BinaryIO, header: SectionHeader) -> None:
        file.seek(header.sh_offset, 0)

        self.data = bytearray(file.read(header.sh_size))

    def to_bytes(self) -> bytes:
        return bytes(self.data)

    def append(self, string: bytes) -> int:
        offset: int = len(self.data)

        self.data += string
        self.data += b"\x00"

        return offset

    def string(self, offset: int) -> bytes:
        try:
            string: bytearray = bytearray()

            while True:
                if self.data[offset] == 0:
                    break

                string.append(self.data[offset])

                offset += 1

            return bytes(string)
        except IndexError:
            raise ValueError("Offset not in table.")

    def offset(self, string: bytes) -> int:
        try:
            return self.data.index(string + b"\x00")
        except ValueError:
            raise ValueError("String not in table.")

    def offset_or_append(self, string: bytes) -> int:
        try:
            return self.offset(string)
        except ValueError:
            return self.append(string)


class SymbolTableEntry:
    name: bytes
    binding: STBind
    type: STType
    visibility: STVisibility
    section_index: int
    value: int
    size: int

    def __init__(
        self,
        file: Optional[BinaryIO] = None,
        elf_header: Optional[ELFHeader] = None,
        string_table: Optional[StringTableSection] = None,
    ) -> None:
        if file is not None and elf_header is not None and string_table is not None:
            self._init_file(file, elf_header, string_table)
        else:
            raise TypeError("Invalid combination of arguments.")

    def _init_file(
        self, file: BinaryIO, elf_header: ELFHeader, string_table: StringTableSection
    ) -> None:
        name_offset: int
        (name_offset,) = unpack(f"{elf_header.endian_format}I", file.read(4))

        self.name = string_table.string(name_offset)

        if elf_header.word_size == 4:
            self.value, self.size = unpack(
                f"{elf_header.endian_format}{elf_header.word_format}{elf_header.word_format}",
                file.read(elf_header.word_size * 2),
            )

        info: int
        other: int
        info, other, self.section_index = unpack(
            f"{elf_header.endian_format}BBH", file.read(4)
        )

        self.binding = STBind(info >> 4)
        self.type = STType(info & ((1 << 4) - 1))

        self.visibility = STVisibility(other & ((1 << 2) - 1))

        if elf_header.word_size == 8:
            self.value, self.size = unpack(
                f"{elf_header.endian_format}{elf_header.word_format}{elf_header.word_format}",
                file.read(elf_header.word_size * 2),
            )

    def to_bytes(
        self,
        word_size: int,
        word_format: int,
        endian_format: int,
        string_table: StringTableSection,
    ) -> bytes:
        result: bytearray = bytearray()

        result += pack(f"{endian_format}I", string_table.offset_or_append(self.name))

        if word_size == 4:
            result += pack(
                f"{endian_format}{word_format}{word_format}", self.value, self.size
            )

        info: int = (self.binding << 4) | self.type

        other: int = self.visibility

        result += pack(f"{endian_format}BBH", info, other, self.section_index)

        if word_size == 8:
            result += pack(
                f"{endian_format}{word_format}{word_format}", self.value, self.size
            )

        return bytes(result)


class SymbolTableSection(Section):
    entries: list[SymbolTableEntry]

    def __init__(
        self,
        file: Optional[BinaryIO] = None,
        header: Optional[SectionHeader] = None,
        elf_header: Optional[ELFHeader] = None,
        string_table: Optional[StringTableSection] = None,
        name: Optional[bytes] = None,
    ) -> None:
        if (
            file is not None
            and header is not None
            and string_table is not None
            and elf_header is not None
            and name is not None
        ):
            super().__init__(
                name,
                header.sh_type,
                header.sh_flags,
                header.sh_addr,
                header.sh_link,
                header.sh_info,
                header.sh_addralign,
                header.sh_entsize,
            )
            self._init_file(file, header, elf_header, string_table)
        else:
            raise TypeError("Invalid combination of arguments.")

    def _init_file(
        self,
        file: BinaryIO,
        header: SectionHeader,
        elf_header: ELFHeader,
        string_table: StringTableSection,
    ) -> None:
        entry_size: int = 8 + (elf_header.word_size * 2)

        # Skip the reserved entry.
        file.seek(header.sh_offset + entry_size, 0)

        self.entries = []
        for _ in range((header.sh_size // entry_size) - 1):
            self.entries.append(
                SymbolTableEntry(
                    file=file, elf_header=elf_header, string_table=string_table
                )
            )

    def to_bytes(
        self,
        word_size: int,
        word_format: int,
        endian_format: int,
        string_table: StringTableSection,
    ) -> bytes:
        result: bytearray = bytearray()

        entry_size: int = 8 + (word_size * 2)

        result += b"\x00" * entry_size

        entry: SymbolTableEntry
        for entry in self.entries:
            result += entry.to_bytes(
                word_size, word_format, endian_format, string_table
            )

        return bytes(result)


class ELF:
    sections: list[Section]

    def __init__(self, file: Optional[BinaryIO] = None) -> None:
        if file is not None:
            self._init_file(file)
        else:
            raise TypeError("Invalid combination of arguments.")

    def _init_file(self, file: BinaryIO) -> None:
        file.seek(0, 0)

        elf_header: ELFHeader = ELFHeader(file=file)

        file.seek(elf_header.e_phoff, 0)

        program_headers: list[ProgramHeader] = []
        for _ in range(elf_header.e_phnum):
            program_headers.append(ProgramHeader(file=file, elf_header=elf_header))

        file.seek(elf_header.e_shoff, 0)

        section_headers: list[SectionHeader] = []
        for _ in range(elf_header.e_shnum):
            section_headers.append(SectionHeader(file=file, elf_header=elf_header))

        shstrtab_header: SectionHeader = section_headers[elf_header.e_shstrndx]

        shstrtab = StringTableSection(
            file=file,
            header=shstrtab_header,
            name=b"",
        )

        shstrtab.name = shstrtab.string(shstrtab_header.sh_name)

        sections: list[Optional[Section]] = [None] * len(section_headers)
        sections[elf_header.e_shstrndx] = shstrtab

        string_table_section: Optional[Section]
        section: Optional[Section]
        section_index: int
        section_header: SectionHeader
        while None in sections:  # Resolve sections until we can get a complete list.
            for section_index, section_header in enumerate(section_headers):
                if sections[section_index] is None:
                    if section_header.sh_type == SHType.SHT_STRTAB:
                        section = StringTableSection(
                            file=file,
                            header=section_header,
                            name=shstrtab.string(section_header.sh_name),
                        )
                    elif section_header.sh_type == SHType.SHT_SYMTAB:
                        if sections[section_header.sh_link] is None:
                            section = None
                        else:
                            string_table_section = sections[section_header.sh_link]

                            assert isinstance(string_table_section, StringTableSection)

                            section = SymbolTableSection(
                                file=file,
                                header=section_header,
                                string_table=string_table_section,
                                elf_header=elf_header,
                                name=shstrtab.string(section_header.sh_name),
                            )
                    else:
                        section = BytesSection(
                            file=file,
                            header=section_header,
                            name=shstrtab.string(section_header.sh_name),
                        )

                    sections[section_index] = section

        self.sections = []
        for section in sections:
            assert section is not None, "UNEXPECTED"

            self.sections.append(section)
