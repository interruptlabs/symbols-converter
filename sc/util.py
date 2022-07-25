from typing import Any


def fnn(*args: Any) -> Any:
    """
    Returns the first not None argument.
    """
    arg: Any
    for arg in args:
        if arg is not None:
            return arg

    return None
