from argparse import Namespace

from sc.ghidra.xml_ import (
    Section as XMLSection,
    SectionPermissions as XMLSectionPermissions,
    XML,
)
from sc.structures import Bundle, Section, SectionFlags, Symbol, SymbolType


def from_ghidra_xml(arguments: Namespace) -> Bundle:
    xml: XML = XML(arguments.ghidra_xml.open("r"))

    bundle: Bundle = Bundle()

    address: int
    name: str
    for address, name in xml.functions.items():
        bundle.symbols.append(Symbol(name.encode(), address, SymbolType.FUNCTION))

    for address, name in xml.globals_.items():
        bundle.symbols.append(Symbol(name.encode(), address, SymbolType.GLOBAL))

    section: XMLSection
    for section in xml.sections:
        flags: SectionFlags = SectionFlags(0)

        if section.permissions & XMLSectionPermissions.R:
            flags |= SectionFlags.R

        if section.permissions & XMLSectionPermissions.W:
            flags |= SectionFlags.W

        if section.permissions & XMLSectionPermissions.X:
            flags |= SectionFlags.X

        bundle.sections.append(
            Section(section.name.encode(), section.start, section.end, flags)
        )

    return bundle
