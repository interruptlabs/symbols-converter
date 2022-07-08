from typing import Sequence


class Entry:
    key: bytes
    value: bytes

    def __init__(self, key: bytes, value: bytes) -> None:
        self.key = key
        self.value = value

    def __repr__(self):
        return f"Entry<key={repr(self.key)}, value={repr(self.value)}"


class LeafEntry(Entry):
    def __repr__(self):
        return f"Leaf{super().__repr__()}>"


class IndexEntry(Entry):
    before_page: "Page"
    after_page: "Page"

    def __init__(
        self, key: bytes, value: bytes, before_page: "Page", after_page: "Page"
    ) -> None:
        super().__init__(key, value)

        self.before_page = before_page
        self.after_page = after_page

    def __repr__(self):
        return f"Index{super().__repr__()}, before_page={repr(self.before_page)}, after_page={repr(self.after_page)}>"


class Page:
    entries: Sequence[Entry]

    def __init__(self, entries: Sequence[Entry]) -> None:
        self.entries = [entry for entry in entries]

    def __repr__(self):
        return f"""Page<entries={repr(self.entries)}"""


class LeafPage(Page):
    entries: Sequence[IndexEntry]

    def __init__(self, entries: Sequence[LeafEntry]) -> None:
        super().__init__(entries)

    def __repr__(self):
        return f"Leaf{super().__repr__()}>"


class IndexPage(Page):
    entries: Sequence[LeafEntry]

    def __init__(self, entries: Sequence[IndexEntry]) -> None:
        super().__init__(entries)

    def __repr__(self):
        return f"Index{super().__repr__()}>"
