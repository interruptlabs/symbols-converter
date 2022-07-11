from struct import calcsize, pack, unpack
from typing import Any, Generator, Optional, Union

from sc.idb.btree.python import Entry
from sc.idb.idb import ID0


def unpack_t(data: bytes, offset: int) -> tuple[int, int]:
    """
    Unpacks up to a two byte value.
    The number of bytes used is one more than the number of proceeding ones.
    """

    first_byte: int = data[offset]

    if first_byte & 0b11000000 == 0b11000000:
        return int.from_bytes(data[offset + 1 : offset + 3], "big"), 3
    elif first_byte & 0b10000000 == 0b10000000:
        return int.from_bytes(data[offset : offset + 2], "big") & 0b011111111111111, 2
    else:
        return first_byte, 1


def unpack_u(data: bytes, offset: int) -> tuple[int, int]:
    """
    Unpacks up to a four byte value.
    The number of bytes used is one or two more than the number of proceeding ones.
    """

    first_byte: int = data[offset]

    if first_byte & 0b11100000 == 0b11100000:
        return int.from_bytes(data[offset + 1 : offset + 5], "big"), 5
    elif first_byte & 0b11000000 == 0b11000000:
        return (
            int.from_bytes(data[offset : offset + 4], "big")
            & 0b00111111111111111111111111111111,
            4,
        )
    elif first_byte & 0b10000000 == 0b10000000:
        return int.from_bytes(data[offset : offset + 2], "big") & 0b0111111111111111, 2
    else:
        return first_byte, 1


def unpack_v(data: bytes, offset: int) -> tuple[int, int]:
    """
    Unpacks up to an eight byte value.
    Represented as two consecutive Us.
    """

    upper_result: int
    upper_size: int
    upper_result, upper_size = unpack_u(data, offset)

    lower_result: int
    lower_size: int
    lower_result, lower_size = unpack_u(data, offset + upper_size)

    return (upper_result << 32) + lower_result, upper_size + lower_size


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

    def unpack(self, format_: str, data: bytes) -> tuple[Any, ...]:
        """
        Extends regular unpack to support IDA's proprietary packing mechanism.

        Adds:
        - T: Up to a two-byte value.
        - U: Up to a four-byte value.
        - V: Up to an eight-byte value.
        - *: Up to a word-size-byte value.
        """

        big_endian: bool = True
        repeat_count: int = 0
        offset: int = 0
        results: list[Any] = []

        size: int
        index: int
        value: str
        for index, value in enumerate(format_):
            if index == 0 and value in "<>":
                if value == "<":
                    big_endian = False

                continue

            if value in "0123456789":
                repeat_count *= 10
                repeat_count += int(value)

                continue

            if repeat_count == 0:
                repeat_count = 1

            if value in "xcbB?hHiIlLqQnNefdspP":  # Regular format specifiers.
                size = calcsize(f"{repeat_count}{value}")

                if big_endian:
                    results += unpack(
                        f">{repeat_count}{value}", data[offset : offset + size]
                    )
                else:
                    results += unpack(
                        f">{repeat_count}{value}", data[offset : offset + size]
                    )

                offset += size
            elif value in "TUV*":  # Custom format specifiers.
                result: int
                for _ in range(repeat_count):
                    if value == "T":
                        result, size = unpack_t(data, offset)
                    elif value == "U" or (value == "*" and self.id0.word_size == 4):
                        result, size = unpack_u(data, offset)
                    elif value == "V" or (value == "*" and self.id0.word_size == 8):
                        result, size = unpack_v(data, offset)
                    else:
                        assert False, "UNEXPECTED"

                    results.append(result)
                    offset += size
            else:
                raise ValueError(
                    f"""Invalid character "{value}" at index {index} in format."""
                )

            repeat_count = 0

        return tuple(results)


class NetNodeGenerator:
    id0: ID0

    def __init__(self, id0: ID0) -> None:
        self.id0 = id0

    def net_node(self, node_id: Union[int, bytes]) -> NetNode:
        return NetNode(self.id0, node_id)
