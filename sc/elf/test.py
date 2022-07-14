from sc.elf.elf import ELF, SymbolTableSection

e = ELF(
    file=open(
        "../../vxworks/wrsdk-vxworks7-raspberrypi4b/vxsdk/bsps/rpi_4_0_1_3_0/vxWorks.sym",
        "rb",
    )
)

assert isinstance(e.sections[18], SymbolTableSection)

print([i.__dict__ for i in e.sections[18].entries])
