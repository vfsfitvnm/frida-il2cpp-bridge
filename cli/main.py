#!/usr/bin/python3

from argparse import ArgumentParser, Namespace
from frida_tools.application import ConsoleApplication
from frida_tools.repl import main


class Application(ConsoleApplication):
    def _needs_target(self) -> bool:
        return True

    def _add_options(self, parser: ArgumentParser) -> None:
        subparsers = parser.add_subparsers(dest='command')

        dump_parser = subparsers.add_parser('dump', help='')
        self._add_dump_arguments(dump_parser)

    def _add_il2cpp_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument('--unity-version', required=False,
                            help='Unity version in case it cannot be detected automatically')

    def _add_dump_arguments(self, parser: ArgumentParser) -> None:
        self._add_il2cpp_arguments(parser)

        parser.add_argument('--cs-output', choices=('none',
                            'flat', 'tree'), default='tree')

    def _initialize(self, parser: ArgumentParser, options: Namespace, args: list[str]) -> None:
        return super()._initialize(parser, options, args)

    def _start(self) -> None:
        self._session.compile_script()


if __name__ == "__main__":
    try:
        Application().run()
    except KeyboardInterrupt:
        pass
