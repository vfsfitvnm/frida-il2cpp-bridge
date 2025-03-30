#!/usr/bin/python3

from pathlib import Path
from frida_tools.application import ConsoleApplication
from time import sleep
import colorama
from timeit import default_timer as timer


NPM_MODULE_PATH = Path(__file__).parent.parent
if NPM_MODULE_PATH.stem != 'frida-il2cpp-bridge':
    NPM_MODULE_PATH /= 'frida-il2cpp-bridge'


class FridaIl2CppBridgeApplication(ConsoleApplication):
    def _start(self) -> None:
        self._fake_dump('mscorlib', 192)
        print(colorama.Cursor.DOWN() + (80 * " "))
        self._fake_dump('GameAssembly', 41)
        self._exit(0)

    def _fake_dump(self, name: str, max: int, delay: float = 0.02):
        start = timer()
        i = 0
        while i <= max:
            self._update_status(
                f'{colorama.Fore.BLUE}{name}{colorama.Fore.RESET}: {i} of {max} classes ({(timer() - start):.2f}s)')
            sleep(delay)
            i += 1


if __name__ == "__main__":
    try:
        FridaIl2CppBridgeApplication().run()
    except KeyboardInterrupt:
        pass
