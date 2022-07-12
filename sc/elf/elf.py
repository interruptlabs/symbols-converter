# https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html

from struct import unpack
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
        p_type: int
        (p_type,) = unpack(f"{elf_header.endian_format}I", file.read(4))

        self.p_type = PType(p_type)

        if elf_header.e_ident_ei_class == EIClass.ELFCLASS64:
            (self.p_flags,) = unpack(f"{elf_header.endian_format}I", file.read(4))

        self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz, self.p_memsz = unpack(
            f"{elf_header.endian_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}{elf_header.word_format}",
            file.read(5 * elf_header.word_size),
        )

        if elf_header.e_ident_ei_class == EIClass.ELFCLASS32:
            (self.p_flags,) = unpack(f"{elf_header.endian_format}I", file.read(4))

        (self.p_align,) = unpack(
            f"{elf_header.endian_format}{elf_header.word_format}", file.read(4)
        )


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
