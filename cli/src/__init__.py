from pathlib import Path
from os import environ
import json


__name__ = environ.get("npm_lifecycle_script", "frida-il2cpp-bridge").strip('"')

NPM_MODULE_PATH = Path(__file__)
while NPM_MODULE_PATH.stem != __name__:
    NPM_MODULE_PATH = NPM_MODULE_PATH.parent

with open(NPM_MODULE_PATH / "package.json", "r", encoding="utf-8") as file:
    __version__ = json.load(file)["version"]
