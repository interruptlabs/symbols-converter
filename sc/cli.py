from argparse import ArgumentParser, Namespace
from pathlib import Path

from sc.idb.extractors import FunctionExtractor, FunctionExtractorFunction
from sc.idb.idb import IDB, SectionFlags
from sc.idb.net_node import NetNodeGenerator


def resolved_file(string: str) -> Path:
    path: Path = Path(string).resolve()

    assert path.is_file(), "Path must be a file."

    return path


def resolved_nonexistent(string: str) -> Path:
    path: Path = Path(string).resolve()

    assert not path.exists(), "Path must not exist."

    return path


def parse_arguments() -> Namespace:
    parser: ArgumentParser = ArgumentParser(
        description="Converts an .idb file to a .sym (ELF) file."
    )

    parser.add_argument(
        "-i",
        "--idb",
        type=resolved_file,
        required=True,
        help="Path of the .idb file (input).",
        metavar="PATH",
    )

    parser.add_argument(
        "-s",
        "--sym",
        type=resolved_nonexistent,
        required=True,
        help="Path of the .sym file (output).",
        metavar="PATH",
    )

    parser.add_argument(
        "-f",
        "--no-functions",
        action="store_true",
        help="Do not include functions in the output.",
    )

    parser.add_argument(
        "-F",
        "--auto-functions",
        action="store_true",
        help="Include automatically named functions in the output.",
    )

    parser.add_argument(
        "-g",
        "--no-globals",
        action="store_true",
        help="Do not include globals in the output.",
    )

    return parser.parse_args()


def from_idb(arguments: Namespace) -> dict[int, bytes]:
    idb = IDB(
        file=arguments.idb.open("rb"),
        sections=SectionFlags.ID0 | SectionFlags.ID1 | SectionFlags.NAM,
    )

    assert idb.id0 is not None, ".idb does not contain ID0 section."
    assert idb.id1 is not None, ".idb does not contain ID1 section."
    assert idb.nam is not None, ".idb does not contain NAM section."

    names = set(idb.nam.names)

    net_node_generator: NetNodeGenerator = NetNodeGenerator(idb.id0)

    function_extractor: FunctionExtractor = FunctionExtractor(net_node_generator)

    functions: dict[int, bytes] = {}
    function: FunctionExtractorFunction
    for function in function_extractor.functions:
        if function.name is not None:
            if not arguments.no_functions:
                functions[function.head_header.start] = function.name

            names.remove(function.head_header.start)
        elif arguments.auto_functions:
            functions[
                function.head_header.start
            ] = f"sub_{function.head_header.start:x}".encode()

    globals_: dict[int, bytes] = {}
    global_: int
    for global_ in names:
        if not arguments.no_globals:
            globals_[global_] = net_node_generator.net_node(global_).name()

    return functions | globals_


def main() -> None:
    arguments: Namespace = parse_arguments()

    symbols: dict[int, bytes] = from_idb(arguments)

    print(symbols)


if __name__ == "__main__":
    main()
