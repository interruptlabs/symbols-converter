from enum import Flag, auto
from typing import Optional, TextIO
from xml.etree import ElementTree
from xml.etree.ElementTree import Element


class SectionPermissions(Flag):
    R = auto()
    W = auto()
    X = auto()


class Section:
    name: str
    start: int
    end: int
    permissions: SectionPermissions

    def __init__(self, element: Element) -> None:
        self.name = element.attrib["NAME"]
        self.start = int(element.attrib["START_ADDR"], 16)
        self.end = self.start + int(element.attrib["LENGTH"], 16)

        self.permissions = SectionPermissions(0)

        if "r" in element.attrib["PERMISSIONS"]:
            self.permissions |= SectionPermissions.R

        if "w" in element.attrib["PERMISSIONS"]:
            self.permissions |= SectionPermissions.W

        if "x" in element.attrib["PERMISSIONS"]:
            self.permissions |= SectionPermissions.X


class XML:
    globals_: dict[int, str]
    functions: dict[int, str]
    sections: list[Section]

    def __init__(self, file: TextIO) -> None:
        root: Element = ElementTree.parse(file).getroot()

        parent_element: Optional[Element]

        parent_element = root.find("SYMBOL_TABLE")
        assert parent_element is not None, "No SYMBOL_TABLE element."

        self.globals_ = {}
        child_element: Element
        for element in parent_element.findall("SYMBOL"):
            self.globals_[int(element.attrib["ADDRESS"], 16)] = element.attrib["NAME"]

        parent_element = root.find("FUNCTIONS")
        assert parent_element is not None, "No FUNCTIONS element."

        self.functions = {}
        for element in parent_element.findall("FUNCTION"):
            self.globals_.pop(int(element.attrib["ENTRY_POINT"], 16), None)
            self.functions[int(element.attrib["ENTRY_POINT"], 16)] = element.attrib[
                "NAME"
            ]

        parent_element = root.find("MEMORY_MAP")
        assert parent_element is not None, "No MEMORY_MAP element."

        self.sections = []
        for element in parent_element.findall("MEMORY_SECTION"):
            try:
                self.sections.append(Section(element))
            except ValueError:
                pass
