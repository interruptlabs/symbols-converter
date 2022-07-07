from os import chdir, system
from pathlib import Path
from sys import argv

base_directory = Path(__file__).parent
chdir(base_directory)

if len(argv) == 2:
    argument = argv[1].strip().lower()
else:
    argument = ""

if argument == "format":
    system("black --exclude vxworks .")
elif argument == "requirements":
    system("pipenv lock -r > requirements.txt")
    system("pipenv lock -r --dev-only > requirements-dev.txt")
elif argument == "test":
    system("mypy --check-untyped-defs --exclude vxworks .")
    system("pytest --ignore vxworks")
elif argument == "test-strict":
    to_check = []

    for child in (base_directory / "sc").iterdir():
        if child.name != "tests" and not child.name.startswith("__"):
            to_check.append(f"sc/{child.name}")

    system(f"""mypy --strict {" ".join(to_check)}""")
else:
    print("Invalid argument.")
