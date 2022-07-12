from sc.elf.elf import ELFHeader

eh = ELFHeader(
    open(
        "../../vxworks/wrsdk-vxworks7-raspberrypi4b/vxsdk/bsps/rpi_4_0_1_3_0/vxWorks.sym",
        "rb",
    )
)

print(eh.e_machine)
