from typing import Any

from sc.idb.extractors import FunctionExtractor, SegmentExtractor
from sc.idb.idb import IDB
from sc.idb.net_node import NetNodeGenerator

idb = IDB(
    open(
        "../../vxworks/tp-link_TL-WR543G_firmware_ida_databases/wr543gv1_070809_modified.idb",
        "rb",
    )
)

assert idb.id0 is not None
assert idb.id1 is not None

nng = NetNodeGenerator(idb.id0)

i: Any

# for i in nng.net_node(b"$ segs").entries(b"S"):
#     print(i)

# for i in nng.net_node(b"$ segstrings").entries(b"S"):
#     print(i)

print(hex(idb.id1.segments[0].start), hex(idb.id1.segments[0].end))

sx = SegmentExtractor(nng)

print(hex(sx.segments[0].start), hex(sx.segments[0].end))

print(sx.segments[0].name)

# for i in nng.net_node(b"$ funcs").entries(b"S"):
#     print(i)

assert idb.nam is not None

for i in idb.nam.names:
    print(hex(i), nng.net_node(i).name())
    # for j in nng.net_node(i).entries(b"S"):
    #     print(f"    {j}")

fx = FunctionExtractor(nng)

for i in fx.functions:
    if i.name is not None:
        print(i.name)
