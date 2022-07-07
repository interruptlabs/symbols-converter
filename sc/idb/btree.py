from struct import unpack
from typing import Type


class Entry:
    key_length: int
    key: bytes
    value_length: int
    value: bytes

    def __init__(self, data: bytes, offset: int, last_key: bytes) -> None:
        pass

    def process_record(self, data: bytes, record_offset: int) -> None:
        (self.key_length,) = unpack("<H", data[record_offset : record_offset + 2])
        record_offset += 2

        self.key = data[record_offset : record_offset + self.key_length]
        record_offset += self.key_length

        (self.value_length,) = unpack("<H", data[record_offset : record_offset + 2])
        record_offset += 2

        self.value = data[record_offset : record_offset + self.value_length]
        record_offset += self.value_length


class IndexEntry(Entry):
    page: int

    def __init__(self, data: bytes, offset: int, last_key: bytes) -> None:
        super().__init__(data, offset, last_key)

        record_offset: int
        self.page, record_offset = unpack("<IH", data[offset : offset + 6])

        self.process_record(data, record_offset)


class LeafEntry(Entry):
    indent: int

    def __init__(self, data: bytes, offset: int, last_key: bytes) -> None:
        super().__init__(data, offset, last_key)

        record_offset: int
        self.indent, record_offset = unpack("<H2xH", data[offset : offset + 6])

        self.process_record(data, record_offset)

        self.key = last_key[0 : self.indent] + self.key


class Page:
    first_page_number: int
    count: int
    entries: list[Entry]

    def __init__(self, data: bytes) -> None:
        self.first_page_number, self.count = unpack("<IH", data[0:6])

        entry_type: Type[Entry]
        if self.first_page_number:
            entry_type = IndexEntry
        else:
            entry_type = LeafEntry

        self.entries = []
        last_key = b""

        for i in range(self.count):
            self.entries.append(entry_type(data, 6 * (i + 1), last_key))
            last_key = self.entries[-1].key
