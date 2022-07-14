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

    def __init__(
        self,
        file: Optional[BinaryIO] = None,
        e_ident_ei_mag: Optional[bytes] = None,
        e_ident_ei_class: Optional[EIClass] = None,
        e_ident_ei_data: Optional[EIData] = None,
        e_ident_ei_version: Optional[EIVersion] = None,
        e_ident_ei_osabi: Optional[EIOSABI] = None,
        e_ident_ei_abiversion: Optional[int] = None,
        e_ident_ei_pad: Optional[bytes] = None,
        e_type: Optional[EType] = None,
        e_machine: Optional[EMachine] = None,
        e_version: Optional[EVersion] = None,
        e_entry: Optional[int] = None,
        e_phoff: Optional[int] = None,
        e_shoff: Optional[int] = None,
        e_flags: Optional[int] = None,
        e_ehsize: Optional[int] = None,
        e_phentsize: Optional[int] = None,
        e_phnum: Optional[int] = None,
        e_shentsize: Optional[int] = None,
        e_shnum: Optional[int] = None,
        e_shstrndx: Optional[int] = None,
    ) -> None:
        if file is not None:
            self._init_file(file)
        elif (
            e_ident_ei_mag is not None
            and e_ident_ei_class is not None
            and e_ident_ei_data is not None
            and e_ident_ei_version is not None
            and e_ident_ei_osabi is not None
            and e_ident_ei_abiversion is not None
            and e_ident_ei_pad is not None
            and e_type is not None
            and e_machine is not None
            and e_version is not None
            and e_entry is not None
            and e_phoff is not None
            and e_shoff is not None
            and e_flags is not None
            and e_ehsize is not None
            and e_phentsize is not None
            and e_phnum is not None
            and e_shentsize is not None
            and e_shnum is not None
            and e_shstrndx is not None
        ):
            self.e_ident_ei_mag = e_ident_ei_mag
            self.e_ident_ei_class = e_ident_ei_class
            self.e_ident_ei_data = e_ident_ei_data
            self.e_ident_ei_version = e_ident_ei_version
            self.e_ident_ei_osabi = e_ident_ei_osabi
            self.e_ident_ei_abiversion = e_ident_ei_abiversion
            self.e_ident_ei_pad = e_ident_ei_pad
            self.e_type = e_type
            self.e_machine = e_machine
            self.e_version = e_version
            self.e_entry = e_entry
            self.e_phoff = e_phoff
            self.e_shoff = e_shoff
            self.e_flags = e_flags
            self.e_ehsize = e_ehsize
            self.e_phentsize = e_phentsize
            self.e_phnum = e_phnum
            self.e_shentsize = e_shentsize
            self.e_shnum = e_shnum
            self.e_shstrndx = e_shstrndx
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
    p_flags: PFlags
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    def __init__(
        self,
        file: Optional[BinaryIO] = None,
        elf_header: Optional[ELFHeader] = None,
        p_type: Optional[PType] = None,
        p_flags: Optional[PFlags] = None,
        p_offset: Optional[int] = None,
        p_vaddr: Optional[int] = None,
        p_paddr: Optional[int] = None,
        p_filesz: Optional[int] = None,
        p_memsz: Optional[int] = None,
        p_align: Optional[int] = None,
    ) -> None:
        if file is not None and elf_header is not None:
            self._init_file(file, elf_header)
        elif (
            p_type is not None
            and p_flags is not None
            and p_offset is not None
            and p_vaddr is not None
            and p_paddr is not None
            and p_filesz is not None
            and p_memsz is not None
            and p_align is not None
        ):
            self.p_type = p_type
            self.p_flags = p_flags
            self.p_offset = p_offset
            self.p_vaddr = p_vaddr
            self.p_paddr = p_paddr
            self.p_filesz = p_filesz
            self.p_memsz = p_memsz
            self.p_align = p_align
        else:
            raise TypeError("Invalid combination of arguments.")

    def _init_file(self, file: BinaryIO, elf_header: ELFHeader) -> None:
        assert elf_header.e_phentsize == 8 + (
            6 * elf_header.word_size
        ), "Program header size mismatch."

        p_type: int
        (p_type,) = unpack(f"{elf_header.endian_format}I", file.read(4))

        self.p_type = PType(p_type)

        p_flags: int
        if elf_header.word_size == 8:
            (p_flags,) = unpack(f"{elf_header.endian_format}I", file.read(4))
            self.p_flags = PFlags(p_flags)

        self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz, self.p_memsz = unpack(
            f"{elf_header.endian_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}",
            file.read(5 * elf_header.word_size),
        )

        if elf_header.word_size == 4:
            (p_flags,) = unpack(f"{elf_header.endian_format}I", file.read(4))
            self.p_flags = PFlags(p_flags)

        (self.p_align,) = unpack(
            f"{elf_header.endian_format}{elf_header.word_format}",
            file.read(elf_header.word_size),
        )

    def to_bytes(self, word_size: int, word_format: str, endian_format: str) -> bytes:
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
        self,
        file: Optional[BinaryIO] = None,
        elf_header: Optional[ELFHeader] = None,
        sh_name: Optional[int] = None,
        sh_type: Optional[SHType] = None,
        sh_flags: Optional[SHFlags] = None,
        sh_addr: Optional[int] = None,
        sh_offset: Optional[int] = None,
        sh_size: Optional[int] = None,
        sh_link: Optional[int] = None,
        sh_info: Optional[int] = None,
        sh_addralign: Optional[int] = None,
        sh_entsize: Optional[int] = None,
    ) -> None:
        if file is not None and elf_header is not None:
            self._init_file(file, elf_header)
        elif (
            sh_name is not None
            and sh_type is not None
            and sh_flags is not None
            and sh_addr is not None
            and sh_offset is not None
            and sh_size is not None
            and sh_link is not None
            and sh_info is not None
            and sh_addralign is not None
            and sh_entsize is not None
        ):
            self.sh_name = sh_name
            self.sh_type = sh_type
            self.sh_flags = sh_flags
            self.sh_addr = sh_addr
            self.sh_offset = sh_offset
            self.sh_size = sh_size
            self.sh_link = sh_link
            self.sh_info = sh_info
            self.sh_addralign = sh_addralign
            self.sh_entsize = sh_entsize
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

    def to_bytes(self, word_size: int, word_format: str, endian_format: str) -> bytes:
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
        type_: Optional[SHType] = None,
        flags: Optional[SHFlags] = None,
        address: Optional[int] = None,
        link: Optional[int] = None,
        info: Optional[int] = None,
        alignment: Optional[int] = None,
        entry_size: Optional[int] = None,
        data: bytes = b"",
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
        elif (
            name is not None
            and type_ is not None
            and flags is not None
            and address is not None
            and link is not None
            and info is not None
            and alignment is not None
            and entry_size is not None
        ):
            super().__init__(
                name, type_, flags, address, link, info, alignment, entry_size
            )
            self.data = data
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
        type_: Optional[SHType] = None,
        flags: Optional[SHFlags] = None,
        address: Optional[int] = None,
        link: Optional[int] = None,
        info: Optional[int] = None,
        alignment: Optional[int] = None,
        entry_size: Optional[int] = None,
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
        elif (
            name is not None
            and type_ is not None
            and flags is not None
            and address is not None
            and link is not None
            and info is not None
            and alignment is not None
            and entry_size is not None
        ):
            super().__init__(
                name, type_, flags, address, link, info, alignment, entry_size
            )
            self.data = bytearray()
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
        word_format: str,
        endian_format: str,
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
        type_: Optional[SHType] = None,
        flags: Optional[SHFlags] = None,
        address: Optional[int] = None,
        link: Optional[int] = None,
        info: Optional[int] = None,
        alignment: Optional[int] = None,
        entry_size: Optional[int] = None,
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
        elif (
            name is not None
            and type_ is not None
            and flags is not None
            and address is not None
            and link is not None
            and info is not None
            and alignment is not None
            and entry_size is not None
        ):
            super().__init__(
                name, type_, flags, address, link, info, alignment, entry_size
            )
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
        word_format: str,
        endian_format: str,
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

    def to_bytes(
        self,
        _64_bit: bool,
        big_endian: bool,
        section_header_string_table_index: Optional[int] = None,
        symbol_table_string_table_index: Optional[int] = None,
        abi: EIOSABI = EIOSABI.ELFOSABI_NONE,
        abi_version: int = 0,
        type_: EType = EType.ET_NONE,
        machine: EMachine = EMachine.EM_NONE,
        entry_pont: int = 0,
        flags: int = 0,
    ) -> bytes:
        section_header_string_table: Section
        if section_header_string_table_index is None:
            section_header_string_table_index = len(self.sections)

            section_header_string_table = StringTableSection(
                name=b".shstrtab",
                type_=SHType.SHT_STRTAB,
                flags=SHFlags(0),
                address=0,
                link=0,
                info=0,
                alignment=1,
                entry_size=0,
            )

            self.sections.append(section_header_string_table)
        else:
            section_header_string_table = self.sections[
                section_header_string_table_index
            ]

        assert section_header_string_table_index is not None, "UNEXPECTED"

        assert isinstance(
            section_header_string_table, StringTableSection
        ), "Section at index is not a string table."

        symbol_table_string_table: Section
        if symbol_table_string_table_index is None:
            symbol_table_string_table_index = len(self.sections)

            symbol_table_string_table = StringTableSection(
                name=b".strtab",
                type_=SHType.SHT_STRTAB,
                flags=SHFlags(0),
                address=0,
                link=0,
                info=0,
                alignment=1,
                entry_size=0,
            )

            self.sections.append(symbol_table_string_table)
        else:
            symbol_table_string_table = self.sections[symbol_table_string_table_index]

        assert symbol_table_string_table_index is not None, "UNEXPECTED"

        assert isinstance(
            symbol_table_string_table, StringTableSection
        ), "Section at index is not a string table."

        elf_header: ELFHeader = ELFHeader(
            e_ident_ei_mag=b"\x7fELF",
            e_ident_ei_class=EIClass.ELFCLASS64 if _64_bit else EIClass.ELFCLASS32,
            e_ident_ei_data=EIData.ELFDATA2MSB if big_endian else EIData.ELFDATA2LSB,
            e_ident_ei_version=EIVersion.EV_CURRENT,
            e_ident_ei_osabi=abi,
            e_ident_ei_abiversion=abi_version,
            e_ident_ei_pad=b"\x00" * 7,
            e_type=type_,
            e_machine=machine,
            e_version=EVersion.EV_CURRENT,
            e_entry=entry_pont,
            e_phoff=0,
            e_shoff=0,
            e_flags=flags,
            e_ehsize=0,
            e_phentsize=0,
            e_phnum=0,
            e_shentsize=0,
            e_shnum=0,
            e_shstrndx=section_header_string_table_index,
        )

        section_header_name_offsets: list[int] = []
        section_header_name_offset: int
        section_bytes: list[Optional[bytes]] = []
        section_bytes_: Optional[bytes]
        section: Section
        for section in self.sections:
            section_header_name_offset = section_header_string_table.offset_or_append(
                section.name
            )
            section_header_name_offsets.append(section_header_name_offset)

            if section in (section_header_string_table, symbol_table_string_table):
                section_bytes_ = None
            else:
                if isinstance(section, BytesSection) or isinstance(
                    section, StringTableSection
                ):
                    section_bytes_ = section.to_bytes()
                elif isinstance(section, SymbolTableSection):
                    section.link = symbol_table_string_table_index
                    section.entry_size = 8 + (elf_header.word_size * 2)

                    section_bytes_ = section.to_bytes(
                        elf_header.word_size,
                        elf_header.word_format,
                        elf_header.endian_format,
                        symbol_table_string_table,
                    )
                else:
                    raise TypeError("Unknown section type.")

            section_bytes.append(section_bytes_)

        section_bytes[
            section_header_string_table_index
        ] = section_header_string_table.to_bytes()
        section_bytes[
            symbol_table_string_table_index
        ] = symbol_table_string_table.to_bytes()

        offset: int = 0
        program_headers: list[ProgramHeader] = []
        section_headers: list[SectionHeader] = []
        for section, section_bytes_, section_header_name_offset in zip(
            self.sections, section_bytes, section_header_name_offsets
        ):
            assert section_bytes_ is not None, "UNEXPECTED"

            if section.flags & SHFlags.SHF_ALLOC:
                program_headers.append(
                    ProgramHeader(
                        p_type=PType.PT_LOAD,
                        p_flags=PFlags.PF_R
                        | (PFlags.PF_W if section.flags & SHFlags.SHF_WRITE else 0)
                        | (PFlags.PF_X if section.flags & SHFlags.SHF_EXECINSTR else 0),
                        p_offset=offset,
                        p_vaddr=section.address,
                        p_paddr=section.address,
                        p_filesz=len(section_bytes_),
                        p_memsz=len(section_bytes_),
                        p_align=section.alignment,
                    )
                )

            section_headers.append(
                SectionHeader(
                    sh_name=section_header_name_offset,
                    sh_type=section.type,
                    sh_flags=section.flags,
                    sh_addr=section.address,
                    sh_offset=offset,
                    sh_size=len(section_bytes_),
                    sh_link=section.link,
                    sh_info=section.info,
                    sh_addralign=section.alignment,
                    sh_entsize=section.entry_size,
                )
            )

            offset += len(section_bytes_)

        elf_header.e_phentsize = 8 + (6 * elf_header.word_size)
        elf_header.e_phnum = len(program_headers)

        elf_header.e_shentsize = 16 + (6 * elf_header.word_size)
        elf_header.e_shnum = len(section_headers)

        elf_header.e_phoff = len(elf_header.to_bytes())

        offset_adjustment: int = elf_header.e_phoff + (
            elf_header.e_phnum * elf_header.e_phentsize
        )

        elf_header.e_shoff = offset + offset_adjustment

        result: list[bytes] = [elf_header.to_bytes()]

        program_header: ProgramHeader
        for program_header in program_headers:
            program_header.p_offset += offset_adjustment

            result.append(
                program_header.to_bytes(
                    elf_header.word_size,
                    elf_header.word_format,
                    elf_header.endian_format,
                )
            )

        for section_bytes_ in section_bytes:
            assert section_bytes_ is not None, "UNEXPECTED"

            result.append(section_bytes_)

        section_header: SectionHeader
        for section_header in section_headers:
            section_header.sh_offset += offset_adjustment

            result.append(
                section_header.to_bytes(
                    elf_header.word_size,
                    elf_header.word_format,
                    elf_header.endian_format,
                )
            )

        return b"".join(result)
