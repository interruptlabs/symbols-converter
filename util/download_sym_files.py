from itertools import count
from os import environ
from pathlib import Path
from time import sleep
from urllib.request import urlretrieve

import requests

try:
    PAT = environ["GITHUB_PAT"]
except IndexError:
    print("Set the GITHUB_PAT environment variable to a personal access token from:")
    print("https://github.com/settings/tokens")
    exit(1)

DOWNLOAD_FOLDER = (Path(__file__).parent.parent / "vxworks" / "syms").resolve()
DOWNLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

downloaded_hashes = set()

for page in count(1):
    results = requests.get(
        "https://api.github.com/search/code",
        headers={"Authorization": f"Token {PAT}"},
        params={"q": "filename:vxworks.sym", "per_page": "100", "page": str(page)},
    ).json()["items"]

    if len(results) == 0:
        break

    for result in results:
        if (
            result["name"].lower() == "vxworks.sym"
            and result["sha"] not in downloaded_hashes
        ):
            downloaded_hashes.add(result["sha"])

            urlretrieve(
                result["html_url"].replace("/blob/", "/raw/"),
                DOWNLOAD_FOLDER / f"""{result["sha"]}.sym""",
            )

            print(result["sha"])

    sleep(60)
