from sc.elf.elf import ELF

e = ELF(
    file=open(
        "../../vxworks/wrsdk-vxworks7-raspberrypi4b/vxsdk/bsps/rpi_4_0_1_3_0/vxWorks.sym",
        "rb",
    )
)

for i in e.sections:
    print(i.__dict__)
