import json
from argparse import Namespace
from pathlib import Path
from typing import TextIO

from sc.structures import Bundle, Symbol, SymbolType


def to_json(arguments: Namespace, bundle: Bundle) -> None:
    json_: dict[str, dict[str, int]] = {"functions": {}, "globals": {}}

    symbol: Symbol
    for symbol in bundle.symbols:
        if symbol.type == SymbolType.FUNCTION:
            json_["functions"][symbol.name.decode()] = symbol.address
        elif symbol.type == SymbolType.GLOBAL:
            json_["globals"][symbol.name.decode()] = symbol.address
        else:
            assert False, "UNEXPECTED"

    if isinstance(arguments.json, Path):
        json_file: TextIO
        with arguments.json.open("w") as json_file:
            json.dump(json_, json_file)
    else:
        json.dump(json_, arguments.json)


def to_txt(arguments: Namespace, bundle: Bundle) -> None:
    txt_file: TextIO
    if isinstance(arguments.txt, Path):
        txt_file = arguments.txt.open("w")
    else:
        txt_file = arguments.txt

    name_padding: int = 0
    address_padding: int = 0
    symbol: Symbol
    for symbol in bundle.symbols:
        name_padding = max(name_padding, len(symbol.name.decode()))
        address_padding = max(address_padding, len(f"{symbol.address:x}"))

    txt_file.write("functions:\n")

    for symbol in bundle.symbols:
        if symbol.type == SymbolType.FUNCTION:
            txt_file.write(
                f"  {symbol.name.decode(): >{name_padding}}: 0x{symbol.address:0{address_padding}x}\n"
            )

    txt_file.write("globals:\n")

    for symbol in bundle.symbols:
        if symbol.type == SymbolType.GLOBAL:
            txt_file.write(
                f"  {symbol.name.decode(): >{name_padding}}: 0x{symbol.address:0{address_padding}x}\n"
            )

    if isinstance(arguments.txt, Path):
        txt_file.close()
