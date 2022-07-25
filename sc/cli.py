from argparse import ArgumentParser, Namespace, _ArgumentGroup
from pathlib import Path
from sys import stdout
from typing import Callable, TextIO, Union

from sc.elf import to_sym
from sc.elf.constants import (
    EIOSABI,
    EMachine,
    EType,
)
from sc.ghidra import from_ghidra_xml
from sc.idb import from_idb
from sc.simple import to_json, to_txt
from sc.structures import Bundle

FROM_MODULES: dict[str, Callable[[Namespace], Bundle]] = {
    "idb": from_idb,
    "ghidra_xml": from_ghidra_xml,
}

TO_MODULES: dict[str, Callable[[Namespace, Bundle], None]] = {
    "sym": to_sym,
    "json": to_json,
    "txt": to_txt,
}


def resolved_file(string: str) -> Path:
    path: Path = Path(string).resolve()

    assert path.is_file(), "Path must be a file."

    return path


def resolved_nonexistent(string: str) -> Path:
    path: Path = Path(string).resolve()

    assert not path.exists(), "Path must not exist."

    return path


def resolved_nonexistent_or_stdout(string: str) -> Union[Path, TextIO]:
    if string == "-":
        return stdout
    else:
        return resolved_nonexistent(string)


def parse_arguments() -> Namespace:
    parser: ArgumentParser = ArgumentParser(
        description="Converts an .idb file to a .sym (ELF) file."
    )

    inputs: _ArgumentGroup = parser.add_argument_group(
        "inputs"
    ).add_mutually_exclusive_group()

    inputs.add_argument(
        "-i",
        "--idb",
        type=resolved_file,
        help="Path of the .idb file (input).",
        metavar="PATH",
    )

    inputs.add_argument(
        "-G",
        "--ghidra-xml",
        type=resolved_file,
        help="Path of the Ghidra .xml file (input).",
        metavar="PATH",
    )

    outputs: _ArgumentGroup = parser.add_argument_group("outputs")

    outputs.add_argument(
        "-s",
        "--sym",
        type=resolved_nonexistent,
        help="Path of the .sym file (output).",
        metavar="PATH",
    )

    outputs.add_argument(
        "-j",
        "--json",
        type=resolved_nonexistent_or_stdout,
        help="Path of the .json file (output).",
        metavar="PATH",
    )

    outputs.add_argument(
        "-t",
        "--txt",
        type=resolved_nonexistent_or_stdout,
        help="Path of the .txt file (output).",
        metavar="PATH",
    )

    options: _ArgumentGroup = parser.add_argument_group("options")

    options.add_argument(
        "-f",
        "--no-functions",
        action="store_true",
        help="Do not include functions in the output.",
    )

    options.add_argument(
        "-F",
        "--auto-functions",
        action="store_true",
        help="Include automatically named functions in the output.",
    )

    options.add_argument(
        "-g",
        "--no-globals",
        action="store_true",
        help="Do not include globals in the output.",
    )

    options.add_argument(
        "-w",
        "--word-size",
        choices=("32", "64"),
        help="The word size of the binary. Defaults to trying to extract from the input file and then 64 bit.",
    )

    options.add_argument(
        "-e",
        "--endianness",
        choices=("little", "big"),
        help="The endianness of the binary. Defaults to trying to extract from the input file and then big endian.",
    )

    idb_options: _ArgumentGroup = parser.add_argument_group("idb options")

    idb_options.add_argument(
        "--verify-checksum", action="store_true", help="Verify IDB section checksums."
    )

    sym_options: _ArgumentGroup = parser.add_argument_group("sym options")

    sym_options.add_argument(
        "--abi", choices=tuple(i.name[9:] for i in EIOSABI), help="Defaults to NONE"
    )

    sym_options.add_argument("--abi-version", type=int, help="Defaults to 0.")

    sym_options.add_argument(
        "--type", choices=tuple(i.name[3:] for i in EType), help="Defaults to NONE."
    )

    sym_options.add_argument(
        "--machine",
        choices=tuple(i.name[3:] for i in EMachine),
        help="Defaults to NONE.",
    )

    sym_options.add_argument("--entry-point", type=int, help="Defaults to 0.")

    sym_options.add_argument("--flags", type=int, help="Defaults to 0.")

    arguments: Namespace = parser.parse_args()

    from_count: int = 0
    key: str
    for key in FROM_MODULES:
        if getattr(arguments, key) is not None:
            from_count += 1

    if from_count != 1:
        parser.error("One input argument is required.")

    to_count: int = 0
    for key in TO_MODULES:
        if getattr(arguments, key) is not None:
            to_count += 1

    if to_count == 0:
        parser.error("At least one output argument is required.")

    if arguments.word_size is None:
        arguments._64_bit = None
    else:
        arguments._64_bit = arguments.word_size == "64"

    if arguments.endianness is None:
        arguments.big_endian = None
    else:
        arguments.big_endian = arguments.endianness == "big"

    if arguments.abi is not None:
        arguments.abi = EIOSABI[f"ELFOSABI_{arguments.abi}"]

    if arguments.type is not None:
        arguments.type = EType[f"ET_{arguments.type}"]

    if arguments.machine is not None:
        arguments.machine = EMachine[f"EM_{arguments.machine}"]

    return arguments


def main() -> None:
    arguments: Namespace = parse_arguments()

    bundle: Bundle
    key: str
    from_function: Callable[[Namespace], Bundle]
    for key, from_function in FROM_MODULES.items():
        if getattr(arguments, key) is not None:
            bundle = from_function(arguments)
            break
    else:
        assert False, "UNEXPECTED"

    to_function: Callable[[Namespace, Bundle], None]
    for key, to_function in TO_MODULES.items():
        if getattr(arguments, key) is not None:
            to_function(arguments, bundle)


if __name__ == "__main__":
    main()
