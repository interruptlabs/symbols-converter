# Notes

## Links

- [Ghidra symbol table detection](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/GnuDemangler/ghidra_scripts/VxWorksSymTab_Finder.java)
- [Blackhat talk](https://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Zhu-Dive-into-VxWorks-Based-IoT-Device-Debug-the-Undebugable-Device.pdf)
- [Chinese article](https://blog.csdn.net/ambercctv/article/details/80595910)
- [Leak (has useful tools)](https://github.com/emuikernel/BDXDaq/tree/master/devel/VxWorks55)

## Thoughts

Ghidra and Blackhat seem to agree on three fields:

- Symbol name (4 byte pointer)
- Symbol address (4 byte pointer)
- Symbol type (4 byte pointer?)

Other fields also seem to exist depending on the version.

Some VxWorks binaries have a `.symtab` section. Is this an embedded symbol table?

```bash
readelf -x .symtab vxWorks | tail -n +3 | cut -d ' ' -f 4-7 | tr -d '\n ' | xxd -r -p > vxWorks.symtab
```

A `.sym` file is created with:

```bash
objcopy --extract-symbol
```

Seems to zero all sections except `.symtab`, `.strtab` and `.shstrtab` .

If `INCLUDE_STANDALONE_SYM_TBL` is disabled, a `.sym` is created.

The `util/download_sym_files.py` script downloads `.sym` files from GitHub to analyse.

## Plans

- Explore the VS code extension. The VSIX package can be obtained [here](https://windriver.gallerycdn.vsassets.io/extensions/windriver/windsdksupport/2.5.4/1656760967976/Microsoft.VisualStudio.Services.VSIXPackage). It is just a zip file.
- Try to build a binary with symbols.
- Maybe setup VxWorks on Raspberry Pi.
- Find a copy of `makeSymTbl.tcl`.
- In the 6.2 kernel developer documentation it mentions using `objcopy` to extract a symbol table. Find the command.
- Find out what `INCLUDE_STANDALONE_SYM_TBL` does.

## Next Steps

- Parse the `ID1` section.
- Extract the symbols.

