#!/usr/bin/python3

from typing import Literal, TypedDict

from argparse import ArgumentParser, Namespace
from pathlib import Path
from timeit import default_timer as timer

import colorama
from frida_tools.application import ConsoleApplication

from dump import Dump, DumpPayload, DUMP_AGENT


NPM_MODULE_PATH = Path(__file__).parent.parent
if NPM_MODULE_PATH.stem != 'frida-il2cpp-bridge':
    NPM_MODULE_PATH /= 'frida-il2cpp-bridge'


class Message(TypedDict):
    class Payload(TypedDict):
        action: Literal['init', 'application', 'dump', 'exit']
        value: dict

    type: Literal['send', 'error']
    payload: Payload


class FridaIl2CppBridgeApplication(ConsoleApplication):
    def __init__(self) -> None:
        self._script = None
        self._dump = None
        self._dump_progress = None
        self._timer = None
        self._application_id = None
        self._application_version = None
        super().__init__()

    def _needs_target(self) -> bool:
        return True

    def _add_options(self, parser: ArgumentParser) -> None:
        subparsers = parser.add_subparsers(
            description="IL2CPP specific commands", dest='command', required=True)

        dump_parser = subparsers.add_parser(
            'dump', help='performs a dump of the target')
        self._add_dump_arguments(dump_parser)

    def _add_dump_arguments(self, parser: ArgumentParser) -> None:
        self._add_il2cpp_arguments(parser)

        parser.add_argument('--cs-output', choices=('none',
                            'flat', 'tree'), default='tree')

    def _add_il2cpp_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument('--unity-version', required=False,
                            help='Unity version in case it cannot be detected automatically')

    def _initialize(self, parser: ArgumentParser, options: Namespace, args: list[str]) -> None:
        if options.command == 'dump':
            self._agent_src = DUMP_AGENT
            self._dump = Dump(output=options.cs_output)
            self._dump_progress = {}
            self._unity_version = options.unity_version

        return super()._initialize(parser, options, args)

    def _start(self) -> None:
        self._script = self._session.create_script(
            name='index',
            source=self._script_prelude() + self._agent_src, runtime=self._runtime)

        self._script.on('message', lambda message, data: self._reactor.schedule(
            lambda: self._process_message(message, data)))

        self._script.load()
        self._resume()

    def _stop(self) -> None:
        self._script.unload()
        self._script = None

    def _process_message(self, message: Message, _) -> None:
        if message['type'] == 'send':
            payload = message['payload']
            action = payload['action']
            value = payload.get('value')

            if action == 'init':
                self._timer = timer()
            elif action == 'application':
                self._application_id = value['id']
                self._application_version = value['version']
            elif action == 'dump':
                self._dump.handle_payload(value)
                self._log_dump_progress(value)
            elif action == 'exit':
                if self._timer:
                    elapsed = timer() - self._timer()
                    self._log('info', f'took {elapsed:.2f}s')
                self._exit(0)
            else:
                raise ValueError(
                    f'Unknown payload action {action}')
        elif message['type'] == 'error':
            self._log('error', message.get('stack', message['description']))
            self._exit(1)

    def _log_dump_progress(self, dump: DumpPayload) -> None:
        if assembly_dump := dump.assembly_dump:
            self._dump_progress[assembly_dump['handle']] = 0
            print(colorama.Cursor.DOWN() + (80 * " "))
        elif class_dump := dump.class_dump:
            self._dump_progress[class_dump['assembly']] += 1
            assembly_dump = self._dump.assemblies[class_dump['assembly']]
        else:
            raise ValueError(f'Unknow dump type "{dump["type"]}"')

        self._update_status(
            f'{colorama.Fore.BLUE}{assembly_dump["name"]}{colorama.Fore.RESET}: {self._dump_progress[assembly_dump["handle"]]} of {assembly_dump["classCount"]} classes')

    def _script_prelude(self) -> str:
        dist = NPM_MODULE_PATH / 'dist'

        with open(dist / 'index.js', mode='r', encoding='utf-8') as file:
            src = file.read()

        with open(dist / 'index.js.map',  mode='r', encoding='utf-8') as file:
            src += f'\nScript.registerSourceMap("/index.js", `{file.read()}`);\n'

        if self._unity_version:
            src += f'\nglobalThis.IL2CPP_UNITY_VERSION = "{self._unity_version}";\n'

        return src


if __name__ == "__main__":
    try:
        FridaIl2CppBridgeApplication().run()
    except KeyboardInterrupt:
        pass
