from typing import Sequence


class Entry:
    key: bytes
    value: bytes

    def __init__(self, key: bytes, value: bytes) -> None:
        self.key = key
        self.value = value


class LeafEntry(Entry):
    pass


class IndexEntry(Entry):
    before_page: "Page"
    after_page: "Page"

    def __init__(
        self, key: bytes, value: bytes, before_page: "Page", after_page: "Page"
    ) -> None:
        super().__init__(key, value)

        self.before_page = before_page
        self.after_page = after_page


class Page:
    entries: Sequence[Entry]

    def __init__(self, entries: Sequence[Entry]):
        self.entries = [entry for entry in entries]


class LeafPage(Page):
    entries: Sequence[IndexEntry]

    def __init__(self, entries: Sequence[LeafEntry]):
        super().__init__(entries)


class IndexPage(Page):
    entries: Sequence[LeafEntry]

    def __init__(self, entries: Sequence[IndexEntry]):
        super().__init__(entries)
