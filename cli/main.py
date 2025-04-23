#!/usr/bin/env python3

from src.app import FridaIl2CppBridgeApplication


if __name__ == "__main__":
    try:
        FridaIl2CppBridgeApplication(commands=[]).run()
    except KeyboardInterrupt:
        pass
