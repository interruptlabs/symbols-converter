from sc.idb.btree.python import IndexEntry, IndexPage, LeafEntry, LeafPage


def test_btree_python():
    page_2_0 = LeafPage(
        [
            LeafEntry(b"\x01\x61", b"\x61\x01"),
            LeafEntry(b"\x05", b"\x05"),
            LeafEntry(b"\x08\x14", b"\x14\x08"),
            LeafEntry(b"\x11", b"\x11"),
        ]
    )
    page_2_1 = LeafPage(
        [
            LeafEntry(b"\x17\x78", b"\x78\x17"),
            LeafEntry(b"\x19", b"\x40"),
        ]
    )
    page_2_2 = LeafPage(
        [
            LeafEntry(b"\x20\x36", b"\x36\x20"),
            LeafEntry(b"\x22\x25", b"\x25\x22"),
        ]
    )
    page_2_3 = LeafPage(
        [
            LeafEntry(b"\x32\x41", b"\x41\x32"),
            LeafEntry(b"\x34\x39", b"\x39\x34"),
            LeafEntry(b"\x36\x86", b"\x86\x36"),
            LeafEntry(b"\x37\x70", b"\x70\x37"),
        ]
    )
    page_2_4 = LeafPage(
        [
            LeafEntry(b"\x51", b"\x51"),
            LeafEntry(b"\x57\x33", b"\x33\x57"),
        ]
    )
    page_2_5 = LeafPage(
        [
            LeafEntry(b"\x58\x63", b"\x63\x58"),
            LeafEntry(b"\x63\x97", b"\x97\x63"),
        ]
    )
    page_2_6 = LeafPage(
        [
            LeafEntry(b"\x69\x36", b"\x36\x69"),
            LeafEntry(b"\x71", b"\x71"),
        ]
    )
    page_2_7 = LeafPage(
        [
            LeafEntry(b"\x79", b"\x79"),
            LeafEntry(b"\x83\x21", b"\x21\x83"),
            LeafEntry(b"\x87\x33", b"\x33\x87"),
        ]
    )
    page_2_8 = LeafPage(
        [
            LeafEntry(b"\x90", b"\x90"),
            LeafEntry(b"\x90\x52", b"\x52\x90"),
            LeafEntry(b"\x94\x72", b"\x72\x94"),
        ]
    )

    page_1_0 = IndexPage(
        [
            IndexEntry(b"\x14\x67", b"\x67\x14", page_2_0, page_2_1),
            IndexEntry(b"\x20", b"\x20", page_2_1, page_2_2),
            IndexEntry(b"\x24", b"\x24", page_2_2, page_2_3),
        ]
    )
    page_1_1 = IndexPage(
        [
            IndexEntry(b"\x57\x74", b"\x74\x57", page_2_4, page_2_5),
            IndexEntry(b"\x67", b"\x67", page_2_5, page_2_6),
            IndexEntry(b"\x78\x71", b"\x71\x78", page_2_6, page_2_7),
            IndexEntry(b"\x88", b"\x88", page_2_7, page_2_8),
        ]
    )

    page_0_0 = IndexPage(
        [
            IndexEntry(b"\x37\x96", b"\x96\x37", page_1_0, page_1_1),
        ]
    )

    test = page_0_0.search(None, None, True, True, True)
    assert test is not None
    assert test.key == b"\x01\x61"
    assert test.value == b"\x61\x01"

    test = page_0_0.search(None, None, False, False, True)
    assert test is not None
    assert test.key == b"\x01\x61"
    assert test.value == b"\x61\x01"

    test = page_0_0.search(None, None, True, True, False)
    assert test is not None
    assert test.key == b"\x94\x72"
    assert test.value == b"\x72\x94"

    test = page_0_0.search(None, None, False, False, False)
    assert test is not None
    assert test.key == b"\x94\x72"
    assert test.value == b"\x72\x94"

    test = page_0_0.search(b"\x20", None, True, True, True)
    assert test is not None
    assert test.key == b"\x20"
    assert test.value == b"\x20"

    test = page_0_0.search(b"\x20", None, False, False, True)
    assert test is not None
    assert test.key == b"\x20\x36"
    assert test.value == b"\x36\x20"

    test = page_0_0.search(b"\x37\x96", b"\x78\x71", True, True, True)
    assert test is not None
    assert test.key == b"\x37\x96"
    assert test.value == b"\x96\x37"

    test = page_0_0.search(b"\x37\x96", b"\x78\x71", False, False, True)
    assert test is not None
    assert test.key == b"\x51"
    assert test.value == b"\x51"

    test = page_0_0.search(b"\x37\x96", b"\x78\x71", True, True, False)
    assert test is not None
    assert test.key == b"\x78\x71"
    assert test.value == b"\x71\x78"

    test = page_0_0.search(b"\x37\x96", b"\x78\x71", False, False, False)
    assert test is not None
    assert test.key == b"\x71"
    assert test.value == b"\x71"
