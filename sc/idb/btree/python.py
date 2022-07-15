from typing import Optional, Sequence


class Entry:
    key: bytes
    value: bytes

    def __init__(self, key: bytes, value: bytes) -> None:
        self.key = key
        self.value = value

    def __repr__(self) -> str:
        return f"Entry<key={repr(self.key)}, value={repr(self.value)}"


class LeafEntry(Entry):
    def __repr__(self) -> str:
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

    def __repr__(self) -> str:
        return f"Index{super().__repr__()}, before_page={repr(self.before_page)}, after_page={repr(self.after_page)}>"


class Page:
    entries: Sequence[Entry]

    def __init__(self, entries: Sequence[Entry]) -> None:
        self.entries = [entry for entry in entries]

    def __repr__(self) -> str:
        return f"""Page<entries={repr(self.entries)}"""

    def search(
        self,
        min_: Optional[bytes] = None,
        max_: Optional[bytes] = None,
        min_inclusive: bool = True,
        max_inclusive: bool = False,
        lowest: bool = True,
    ) -> Optional[Entry]:
        if (
            min_ is not None
            and max_ is not None
            and (
                min_ > max_ or (min_ == max_ and not (min_inclusive and max_inclusive))
            )
        ):
            return None

        entry_: Entry
        entry: Optional[Entry] = None
        # TODO: Replace with binary search.
        if lowest:
            for entry_ in self.entries:
                if (
                    min_ is None
                    or (min_inclusive and (entry_.key >= min_))
                    or (not min_inclusive and (entry_.key > min_))
                ):
                    entry = entry_
                    break
        else:
            for entry_ in self.entries[::-1]:
                if (
                    max_ is None
                    or (max_inclusive and (entry_.key <= max_))
                    or (not max_inclusive and (entry_.key < max_))
                ):
                    entry = entry_
                    break

        entry = self.refine_search(
            entry,
            min_=min_,
            max_=max_,
            min_inclusive=min_inclusive,
            max_inclusive=max_inclusive,
            lowest=lowest,
        )

        if entry is None:
            return None

        if lowest:
            if (
                max_ is None
                or (max_inclusive and (entry.key <= max_))
                or (not max_inclusive and (entry.key < max_))
            ):
                return entry
        else:
            if (
                min_ is None
                or (min_inclusive and (entry.key >= min_))
                or (not min_inclusive and (entry.key > min_))
            ):
                return entry

        return None

    def refine_search(
        self,
        entry: Optional[Entry],
        min_: Optional[bytes] = None,
        max_: Optional[bytes] = None,
        min_inclusive: bool = True,
        max_inclusive: bool = False,
        lowest: bool = True,
    ) -> Optional[Entry]:
        return entry


class LeafPage(Page):
    entries: Sequence[LeafEntry]

    def __init__(self, entries: Sequence[LeafEntry]) -> None:
        super().__init__(entries)

    def __repr__(self) -> str:
        return f"Leaf{super().__repr__()}>"


class IndexPage(Page):
    entries: Sequence[IndexEntry]

    def __init__(self, entries: Sequence[IndexEntry]) -> None:
        super().__init__(entries)

    def __repr__(self) -> str:
        return f"Index{super().__repr__()}>"

    def refine_search(
        self,
        entry: Optional[Entry],
        min_: Optional[bytes] = None,
        max_: Optional[bytes] = None,
        min_inclusive: bool = True,
        max_inclusive: bool = False,
        lowest: bool = True,
    ) -> Optional[Entry]:
        page: Page
        if entry is None:
            if lowest:
                page = self.entries[-1].after_page
            else:
                page = self.entries[0].before_page
        else:
            assert isinstance(entry, IndexEntry), "UNEXPECTED"

            page = entry.before_page if lowest else entry.after_page

        return (
            page.search(
                min_=min_,
                max_=max_,
                min_inclusive=min_inclusive,
                max_inclusive=max_inclusive,
                lowest=lowest,
            )
            or entry
        )
