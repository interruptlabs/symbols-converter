from struct import pack, unpack
from typing import Generator, Optional, Union

from sc.idb.btree.python import Entry
from sc.idb.idb import ID0


class NetNode:
    id0: ID0
    node_id: int
    node_base: int

    def __init__(self, id0: ID0, node_id: Union[int, bytes]) -> None:
        self.id0 = id0

        if isinstance(node_id, int):
            self.node_id = node_id
        elif isinstance(node_id, bytes):
            key: bytes = b"N" + node_id

            entry: Optional[Entry] = self.id0.root_page.search(
                min_=key, max_=key, min_inclusive=True, max_inclusive=True, lowest=True
            )

            if entry is None:
                raise ValueError("Invalid node ID.")
            else:
                self.node_id = int.from_bytes(entry.value, "little", signed=False)
        else:
            raise ValueError("Invalid node ID type.")

        self.node_base = 0xFF << ((self.id0.word_size - 1) * 8)

    def make_key(self, tag: bytes, index: Optional[int] = None) -> bytes:
        if index is None:
            return pack(f">c{self.id0.word_format}c", b".", self.node_id, tag)
        elif index < 0:
            return pack(
                f">c{self.id0.word_format}c{self.id0.word_format.lower()}",
                b".",
                self.node_id,
                tag,
                index,
            )
        else:
            return pack(
                f">c{self.id0.word_format}c{self.id0.word_format}",
                b".",
                self.node_id,
                tag,
                index,
            )

    def break_key(
        self, key: bytes, signed: bool = False
    ) -> tuple[bytes, Optional[int]]:
        dot: bytes
        node_id: int
        tag: bytes
        index: Optional[int]
        if len(key) == 2 + self.id0.word_size:
            dot, node_id, tag = unpack(f">c{self.id0.word_format}c", key)
            index = None
        elif len(key) == 2 + (self.id0.word_size * 2) and signed:
            dot, node_id, tag, index = unpack(
                f">c{self.id0.word_format}c{self.id0.word_format.lower()}", key
            )
        elif len(key) == 2 + (self.id0.word_size * 2):
            dot, node_id, tag, index = unpack(
                f">c{self.id0.word_format}c{self.id0.word_format}", key
            )
        else:
            raise KeyError("Invalid key size.")

        if dot != b".":
            raise KeyError("Invalid key.")

        if node_id != self.node_id:
            raise KeyError("Key does not belong to this node.")

        return tag, index

    def key_tag(self, key: bytes) -> bytes:
        return self.break_key(key)[0]

    def key_index(self, key: bytes, signed: bool = False) -> int:
        index: Optional[int]
        _, index = self.break_key(key, signed=signed)

        if index is None:
            raise KeyError("Key does not have index.")

        return index

    def name(self) -> bytes:
        key: bytes = self.make_key(b"N")

        entry: Optional[Entry] = self.id0.root_page.search(
            min_=key, max_=key, min_inclusive=True, max_inclusive=True, lowest=True
        )

        if entry is None:
            raise KeyError("Name does not exist.")
        else:
            return entry.value

    def entry(self, tag: bytes, index: int) -> Entry:
        key: bytes = self.make_key(tag, index=index)

        entry: Optional[Entry] = self.id0.root_page.search(
            min_=key, max_=key, min_inclusive=True, max_inclusive=True, lowest=True
        )

        if entry is None:
            raise KeyError(f"Entry for tag {tag!r} at {index} does not exist.")
        else:
            return entry

    def entries(self, tag: bytes) -> Generator[Entry, None, None]:
        first_key: bytes = self.make_key(tag)
        key = first_key

        while True:
            entry: Optional[Entry] = self.id0.root_page.search(
                min_=key,
                max_=None,
                min_inclusive=False,
                max_inclusive=True,
                lowest=True,
            )

            if entry is None or not entry.key.startswith(first_key):
                break

            yield entry

            key = entry.key

    def alt(self, index: int) -> int:
        return int.from_bytes(self.entry(b"A", index).value, "little", signed=True)

    def alts(self, signed: bool = False) -> Generator[tuple[int, int], None, None]:
        entry: Entry
        for entry in self.entries(b"A"):
            yield self.key_index(entry.key, signed=signed), int.from_bytes(
                entry.value, "little", signed=True
            )

    def hash(self, index: int) -> bytes:
        return self.entry(b"H", index).value

    def hashes(self, signed: bool = False) -> Generator[tuple[int, bytes], None, None]:
        entry: Entry
        for entry in self.entries(b"H"):
            yield self.key_index(entry.key, signed=signed), entry.value

    def sup(self, index) -> bytes:
        return self.entry(b"S", index).value

    def sups(self, signed: bool = False) -> Generator[tuple[int, bytes], None, None]:
        entry: Entry
        for entry in self.entries(b"S"):
            yield self.key_index(entry.key, signed=signed), entry.value

    def value(self, index) -> bytes:
        return self.entry(b"V", index).value

    def values(self, signed: bool = False) -> Generator[tuple[int, bytes], None, None]:
        entry: Entry
        for entry in self.entries(b"V"):
            yield self.key_index(entry.key, signed=signed), entry.value


class NetNodeGenerator:
    id0: ID0

    def __init__(self, id0: ID0) -> None:
        self.id0 = id0

    def net_node(self, node_id: Union[int, bytes]) -> NetNode:
        return NetNode(self.id0, node_id)
