from sc.idb.idb import IDB
from sc.idb.net_node import NetNodeGenerator

idb = IDB(
    open(
        "../../vxworks/tp-link_TL-WR543G_firmware_ida_databases/wr543gv1_070809.idb",
        "rb",
    )
)

assert idb.id0 is not None

nng = NetNodeGenerator(idb.id0)

for i in nng.net_node(b"$ funcs").entries(b"S"):
    print(i)
