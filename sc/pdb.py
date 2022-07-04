# https://llvm.org/docs/PDB/index.html


from __future__ import annotations

from io import BytesIO
from struct import pack, unpack
from typing import BinaryIO, Optional

DEFAULT_BLOCK_SIZE = 1 << 12
MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\x00\x00\x00"


def size_blocks(size_bytes: int, block_size: int = DEFAULT_BLOCK_SIZE) -> int:
    # https://gist.github.com/Diggsey/cefdbd068c540a4d0daa
    if size_bytes == 0xffffffff:
        return 0
    else:
        return (size_bytes + (block_size - 1)) // block_size


def next_block_index(block_index: int, repeat: int = 0, block_size: int = DEFAULT_BLOCK_SIZE) -> int:
    for _ in range(repeat + 1):
        block_index = block_index + 1

        while block_index % block_size in (1, 2):
            block_index += 1

    return block_index


def free_block_map_block(size: int, block_size: int = DEFAULT_BLOCK_SIZE) -> bytes:
    result: bytes = b"\xff" * (size // 8)

    if size % 8 != 0:
        remainder: int = 0

        for _ in range(size % 8):
            remainder <<= 1
            remainder |= 1

        for _ in range(8 - (size % 8)):
            remainder <<= 1
            remainder |= 0

        result += bytes((remainder,))

    result += b"\x00" * (block_size - len(result))

    return result


def high_mod(x: int, y: int) -> int:
    x = x % y

    if x == 0:
        return y
    else:
        return x


class MSF:
    streams: list[Optional[BinaryIO]]

    def __init__(self, file: Optional[BinaryIO] = None) -> None:
        self.streams = []

        if file is not None:
            file.seek(0)

            magic: bytes = file.read(len(MAGIC))
            assert magic == MAGIC, "Invalid magic."

            block_size: int
            free_block_map_index: int
            num_blocks: int
            stream_directory_size_bytes: int
            block_map_index: int
            block_size, free_block_map_index, num_blocks, stream_directory_size_bytes, _, block_map_index = unpack("<IIIIII", file.read(4 * 6))

            stream_directory_size_blocks: int = size_blocks(stream_directory_size_bytes, block_size=block_size)

            file.seek(block_map_index * block_size)

            stream_directory_indexes: list[int] = []
            for _ in range(stream_directory_size_blocks):
                stream_directory_indexes.append(unpack("<I", file.read(4))[0])

            stream_directory: BinaryIO = BytesIO()

            stream_directory_index: int
            for stream_directory_index in stream_directory_indexes:
                file.seek(stream_directory_index * block_size)

                if stream_directory_index == stream_directory_indexes[-1]:
                    stream_directory.write(file.read(high_mod(stream_directory_size_bytes, block_size)))
                else:
                    stream_directory.write(file.read(block_size))

            assert stream_directory.tell() == stream_directory_size_bytes, "Stream directory size mismatch."

            stream_directory.seek(0)

            num_streams: int = unpack("<I", stream_directory.read(4))[0]

            stream_sizes_bytes: list[int] = []
            for _ in range(num_streams):
                stream_sizes_bytes.append(unpack("<I", stream_directory.read(4))[0])

            streams_indexes: list[Optional[list[int]]] = []
            stream_size_bytes: int
            for stream_size_bytes in stream_sizes_bytes:
                # https://gist.github.com/Diggsey/cefdbd068c540a4d0daa
                if stream_size_bytes == 0xffffffff:
                    streams_indexes.append(None)
                else:
                    streams_indexes.append([])

                    assert streams_indexes[-1] is not None

                    for _ in range(size_blocks(stream_size_bytes, block_size=block_size)):
                        streams_indexes[-1].append(unpack("<I", stream_directory.read(4))[0])

            stream_indexes: Optional[list[int]]
            for stream_size_bytes, stream_indexes in zip(stream_sizes_bytes, streams_indexes):
                if stream_indexes is None:
                    self.streams.append(None)
                else:
                    self.streams.append(BytesIO())

                    assert self.streams[-1] is not None

                    stream_index: int
                    for stream_index in stream_indexes:
                        file.seek(stream_index * block_size)

                        if stream_index == stream_indexes[-1]:
                            self.streams[-1].write(file.read(high_mod(stream_size_bytes, block_size)))
                        else:
                            self.streams[-1].write(file.read(block_size))

                    self.streams[-1].seek(0)

    def new_stream(self) -> BinaryIO:
        self.streams.append(BytesIO())

        assert self.streams[-1] is not None

        return self.streams[-1]

    def write(self, file: BinaryIO, block_size: int = DEFAULT_BLOCK_SIZE) -> None:
        stream_size_bytes: int
        stream_sizes_bytes: list[int] = []
        stream: Optional[BinaryIO]
        for stream in self.streams:
            # https://gist.github.com/Diggsey/cefdbd068c540a4d0daa
            if stream is None:
                stream_size_bytes = 0xffffffff
            else:
                stream.seek(0, 2)
                stream_size_bytes = stream.tell()

                assert stream_size_bytes < 0xffffffff, "Stream too large."

            stream_sizes_bytes.append(stream_size_bytes)

        stream_sizes_blocks: list[int] = [size_blocks(stream_size_bytes, block_size=block_size) for stream_size_bytes in stream_sizes_bytes]

        stream_directory_size_bytes: int = (1 + len(self.streams) + sum(stream_sizes_blocks)) * 4
        stream_directory_size_blocks: int = size_blocks(stream_directory_size_bytes, block_size=block_size)

        stream_directory: BinaryIO = BytesIO()

        stream_directory.write(pack("<I", len(self.streams)))

        for stream_size_bytes in stream_sizes_bytes:
            stream_directory.write(pack("<I", stream_size_bytes))

        block_index: int = next_block_index(0, repeat=1 + stream_directory_size_blocks, block_size=block_size)
        stream_size_blocks: int
        for stream_size_blocks in stream_sizes_blocks:
            for _ in range(stream_size_blocks):
                stream_directory.write(pack("<I", block_index))
                block_index = next_block_index(block_index, block_size=block_size)

        num_blocks: int = block_index

        block_map: BinaryIO = BytesIO()

        block_index = next_block_index(0, repeat=1, block_size=block_size)
        for _ in range(stream_directory_size_blocks):
            block_map.write(pack("<I", block_index))
            block_index = next_block_index(block_index, block_size=block_size)

        super_block: BinaryIO = BytesIO()

        super_block.write(MAGIC)
        super_block.write(pack("<IIIIII", block_size, 1, num_blocks, stream_directory_size_bytes, 0, 3))

        header_streams: list[Optional[BinaryIO]] = [super_block, block_map, stream_directory]
        streams: list[Optional[BinaryIO]] = header_streams + self.streams

        block_index = 0
        bits_written: int = 0
        block: bytes
        for stream in streams:
            if stream is not None:
                stream.seek(0)
                while True:
                    block = stream.read(block_size)

                    if len(block) == 0:
                        break

                    file.write(block)

                    if len(block) != block_size:
                        file.write(b"\x00" * (block_size - (len(block) % block_size)))

                    block_index += 1

                    if block_index % block_size in (1, 2):
                        assert block_index % block_size != 2, "UNEXPECTED"

                        bits_size: int = (num_blocks - bits_written) % (block_size * 8)

                        file.write(free_block_map_block(bits_size, block_size=block_size))

                        bits_written += bits_size

                        file.write(free_block_map_block(0, block_size=block_size))

                        block_index += 2

                    if len(block) != block_size:
                        break


if __name__ == '__main__':
    msf = MSF(file=open("/Users/oshawk/Documents/PwnAdventure3/PwnAdventure3/Binaries/Win32/GameLogic.pdb", "rb"))
    msf.write(file=open("/Users/oshawk/Documents/PwnAdventure3/PwnAdventure3/Binaries/Win32/GameLogicM.pdb", "wb"))
