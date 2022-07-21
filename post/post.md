# IDA Database

## Introduction

This post will talk about the structure of an IDA Database (`.idb` or `.i64`) file. IDA databases can contain up to six sections (`ID0`, `ID1`, `NAM`, `SEG`, `TIL` and `ID2`), but only `ID0` and `NAM` will be covered here.

Integers are unsigned little-endian unless otherwise specified.

Most of this information was obtained through reviewing the code of the following amazing projects:

- https://github.com/williballenthin/python-idb
- https://github.com/nlitsme/pyidbutil
- https://github.com/Vector35/idb-parser-rs
- https://github.com/aerosoul94/tilutil

## Header

| Offset | Size | Field          | Purpose                                                      |
| ------ | ---- | -------------- | ------------------------------------------------------------ |
| 0x00   | 4    | `magic`        | Should be either `IDA0`, `IDA1` or `IDA2`. `IDA0` and `IDA1` imply that the file has a 32-bit word size, `IDA2` implies that it has a 64-bit word size. |
| 0x06   | 8    | `id0_offset`   | Offset to the `ID0` section from the start of the file.      |
| 0x0d   | 8    | `id1_offset`   | Offset to the `ID1` section from the start of the file.      |
| 0x1a   | 4    | `signature`    | Should be `0xaabbccdd`.                                      |
| 0x1e   | 2    | `version`      | Should be `6`.                                               |
| 0x20   | 8    | `nam_offset`   | Offset to the `NAM` section from the start of the file.      |
| 0x28   | 8    | `seg_offset`   | Offset to the `SEG` section from the start of the file.      |
| 0x30   | 8    | `til_offset`   | Offset to the `TIL` section from the start of the file.      |
| 0x38   | 4    | `id0_checksum` | CRC32 checksum of the `ID0` section.                         |
| 0x3c   | 4    | `id1_checksum` | CRC32 checksum of the `ID1` section.                         |
| 0x40   | 4    | `nam_checksum` | CRC32 checksum of the `NAM` section.                         |
| 0x44   | 4    | `seg_checksum` | CRC32 checksum of the `SEG` section.                         |
| 0x48   | 4    | `til_checksum` | CRC32 checksum of the `TIL` section.                         |
| 0x4c   | 8    | `id2_offset`   | Offset to the `ID2` section from the start of the file.      |
| 0x50   | 4    | `id2_checksum` | CRC32 checksum of the `ID2` section.                         |

## Section Header

All sections have the following header. The section contents start immediately after.

| Offset | Size | Field                | Purpose                                           |
| ------ | ---- | -------------------- | ------------------------------------------------- |
| 0x00   | 1    | `compression_method` | `0` for no compression. `2` for Zlib compression. |
| 0x01   | 8    | `section_length`     | The length of the section (before decompression). |

## `ID0`

### Header

| Offset | Size | Field             | Purpose                                        |
| ------ | ---- | ----------------- | ---------------------------------------------- |
| 0x00   | 4    | `next_free_index` | The index of the next free page.               |
| 0x04   | 2    | `page_size`       | The number of bytes occupied by a single page. |
| 0x06   | 4    | `root_page_index` | The index of the root page.                    |
| 0x0a   | 4    | `record_count`    | The number of non-dead records.                |
| 0x0e   | 4    | `page_count`      | The number of non-dead pages.                  |
| 0x13   | 9    | `magic`           | Should be `B-tree v2`.                         |

`page_size - 0x1c` bytes of padding follow the header.

### B-Tree

#### Introduction

The contents of `ID0` are laid out as a B-tree. A B-tree is similar to a binary search tree except that each page (collection of records) may have more than two. Each record has a key (shown in the diagram below) and a value.

![](b_tree.png)

#### Page

Every page starts with the following header:

| Offset | Size | Field              | Purpose                                                      |
| ------ | ---- | ------------------ | ------------------------------------------------------------ |
| 0x00   | 4    | `first_page_index` | The index of the first (left-most) child page. If this is `0` then the page is a leaf page, otherwise it is an index page. |
| 0x04   | 2    | `count`            | The number of records in the page.                           |

Following this there is a `count` length array of record meta structures.

#### Index Record Meta

| Offset | Size | Field           | Purpose                                                 |
| ------ | ---- | --------------- | ------------------------------------------------------- |
| 0x00   | 4    | `page_index`    | The index of the child page to the right of the record. |
| 0x04   | 2    | `record_offset` | The offset from the start of the page to the record.    |

#### Leaf Record Meta

| Offset | Size | Field           | Purpose                                                      |
| ------ | ---- | --------------- | ------------------------------------------------------------ |
| 0x00   | 4    | `indent`        | The number of bytes to prepend to this record's key from the start of the last (next-left) record's key. |
| 0x04   | 2    | `record_offset` | The offset from the start of the page to the record.         |

#### Record

Each field follows immediately from the last.

| Size           | Field          | Purpose                                            |
| -------------- | -------------- | -------------------------------------------------- |
| 2              | `key_length`   | The length of the record's key (without `indent`). |
| `key_length`   | `key`          | The record's key.                                  |
| 2              | `value_length` | The length of the record's value.                  |
| `value_length` | `value`        | The record's value.                                |

### Net Nodes

#### Introduction

Net nodes are IDA's method of grouping records related to something (often an address). Each net node has an integer node ID. It may also have a string node ID which can be resolved to the integer node ID.

The records inside a net node are identified by a tag (single byte value) and index (4 or 8 byte value). The B-tree structure makes it efferent to find all records with a given tag.

#### String Node ID

String node IDs can be resolved to integer node IDs by searching the B-tree for a record with the key:

```plain
N<string_node_id>
```

The record's value gives the integer node ID.

#### Name

Some nodes have a string name. This can be found by searching the B-tree for a record with the key:

```plain
.<node_id>N
```

`node_id` is big-endian with a size matching file's word size (see [Header](#header)). The record's value gives the name.

#### Records

You can find an record with a specific index and tag by searching for the key:

```plain
.<node_id><tag><index>
```

Both `node_id` and `index` are big-endian with sizes matching the file's word size.

All records with a given tag can be found by performing a ranged search on the B-tree.

#### Variable Length Integers

Entry values often use IDA's proprietary variable length integer formats.

- Up to two bytes (`T`):
  - If the first byte begins with `0b11`, the value is stored in the following two bytes.
  - Else if the first byte begins with `0b1`, the value is stored in the remainder of the first byte and the following byte.
  - Else the value is stored in the first byte.
- Up four bytes (`U`):
  - If the first byte begins with `0b111`, the value is stored in the following four bytes.
  - Else if the first byte begins with `0b11`, the value is stored in the remainder of the first byte and the following four bytes.
  - Else if the first byte begins with `0b1`, the value is stored in the remainder of the first byte and the following byte.
  - Else the value is stored in the first byte.
- Up to eight bytes (`V`) - Stored as two consecutive `U`s. The fist `U` is the lower four bytes, the second is the upper four bytes.
- Up to word size (`W`) - `U` if the word size if the file's word size is 32-bits and `V` if it is 64-bits.

All are big endian.

### Analysis

Types use the letters from [Variable Length Integers](#variable-length-integers). Upper-case means unsigned and lower-case means signed.

#### Segments (Sections)

Segment information is found in the `$ funcs` net node. Every record with the tag `S` has the format:

| Type | Field               | Description                                                  |
| ---- | ------------------- | ------------------------------------------------------------ |
| `W`  | `start`             | The start address of the segment.                            |
| `W`  | `length`            | The length of the segment.                                   |
| `W`  | `name_index`        | The index of the segment's name in `$ segstrings` (covered later). |
| `W`  | `class_index`       | The index of the segment's class in `$ segstrings` (covered later). |
| `W`  | `org_base`          | Dependant on the processor.                                  |
| `U`  | `flags`             | Detailed [here](https://www.hex-rays.com/products/ida/support/sdkdoc/group___s_f_l__.html). |
| `U`  | `alignment_codes`   | Unknown.                                                     |
| `U`  | `combination_codes` | Unknown.                                                     |
| `U`  | `permissions`       | Flags. `1` is read, `2` is write, `4` is execute. `0` means unknown flags. |
| `U`  | `bitness`           | The number of bits used for segment addressing. `0` is 16-bits, `1` is 32-bits, `2` is 64-bits. |
| `U`  | `type`              | Determines how the kernel deals with the segment.            |
| `U`  | `selector`          | A unique value used to identify the segment.                 |
| `U`  | `colour`            | The segment's colour. Subtract one for the RGBA value.       |

The `$ segstrings` net node has a record with tag `S` at index `0`. This is an array of:

```plain
<string_length><string>
```

Where the string length is a single byte.

#### Functions

Function information is found in the `$ funcs` net node. Every record with the tag `S` begins with:

| Type | Field    | Description                                                  |
| ---- | -------- | ------------------------------------------------------------ |
| `W`  | `start`  | The start address of the function chunk.                     |
| `W`  | `length` | The length of the function chunk.                            |
| `T`  | `flags`  | Flags. `0x8000` means this is a tail chunk (it is a head chunk otherwise). |

Head chunks then have the following:

| Type | Field            | Description                              |
| ---- | ---------------- | ---------------------------------------- |
| `W`  | `frame`          | The node ID of the frame net node.       |
| `W`  | `locals_size`    | The size of the local variables (bytes). |
| `T`  | `registers_size` | The size of the saved registers (bytes). |
| `W`  | `arguments_size` | The size of the stack arguments (bytes). |

And tail chunks have:

| Type | Field           | Description                                                  |
| ---- | --------------- | ------------------------------------------------------------ |
| `w`  | `parent_offset` | The offset to the head chunk. Subtract this from `start` to get the address of the head chunk. |
| `U`  | `referer_count` | The number of referrers referencing this chunk.              |

Every function has one head chunk and zero or more tail chunks. The name of the head chunk is the function name.

The information documented here is only part of the function information that is available.

## `NAM`

### Header

| Offset 32 | Offset 64 | Size | Field        | Purpose                                                      |
| --------- | --------- | ---- | ------------ | ------------------------------------------------------------ |
| 0x00      | 0x00      | 4    | `magic`      | Should be `VA*` followed by a null byte.                     |
| 0x08      | 0x08      | 4    | `non_empty`  | `0` if the section is empty, `1` otherwise.                  |
| 0x10      | 0x10      | 4    | `page_count` | The number of pages (size `0x2000`) occupied by the section. |
| 0x18      | 0x1c      | 4    | `name_count` | The number of name addresses in the section. If the file's word size is 64-bit's then this number needs to be halved. |

If the file's word size is 32-bits then `0x1fe4` bytes of padding follow the header and if it is 64-bits then `0x1fe0` bytes of padding follow it.

### Name Addresses

A `name_count` array if integers matching the file's word size. To resolve the integer's to strings see [Name](#name).