#!/usr/bin/env python3

from src.app import FridaIl2CppBridgeApplication
from src.dump.command import DumpCommand


if __name__ == "__main__":
    try:
        FridaIl2CppBridgeApplication(commands=[DumpCommand]).run()
    except KeyboardInterrupt:
        pass
