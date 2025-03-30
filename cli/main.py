#!/usr/bin/python3

from argparse import ArgumentParser, Namespace
from pathlib import Path
from frida_tools.application import ConsoleApplication
from frida_tools.repl import REPLApplication
from dump import Dump, DumpPayload


NPM_MODULE_PATH = Path(__file__).parent.parent
if NPM_MODULE_PATH.stem != 'frida-il2cpp-bridge':
    NPM_MODULE_PATH /= 'frida-il2cpp-bridge'


class FridaIl2CppBridgeApplication(ConsoleApplication):
    def __init__(self) -> None:
        self._script = None
        self._dump = None
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
            self._dump = Dump()
            self._unity_version = options.unity_version
            self._cs_output = options.cs_output

        return super()._initialize(parser, options, args)

    def _start(self) -> None:
        self._script = self._session.create_script(
            name='index',
            source=self._script_source(self._agent_src), runtime=self._runtime)

        self._script.on('message', lambda message, data: self._reactor.schedule(
            lambda: self._process_message(message, data)))

        self._script.load()
        self._resume()

    def _stop(self) -> None:
        self._script.unload()
        self._script = None

    def _process_message(self, message: dict, _: str | dict) -> None:
        if message['type'] == 'send':
            payload = message['payload']
            match payload['action']:
                case 'dump':
                    if payload['type'] == 'assembly':
                        self._log(
                            'info', f'Dumping {payload['value']['name']} ({payload['value']['classCount']} classes)...')
                    elif payload['type'] == 'class':
                        pass

                    self._dump.handle_payload(payload)
                case 'exit':
                    self._exit(0)
                case unknown_action:
                    raise ValueError(
                        f'Unknown message payload action "{unknown_action}"')
        elif message['type'] == 'error':
            self._log('error', message.get('stack', message['description']))
            self._exit(1)

    @staticmethod
    def _script_source(agent: str) -> str:
        dist = NPM_MODULE_PATH / 'dist'

        with open(dist / 'index.js', mode='r', encoding='utf-8') as file:
            index_js = file.read()

        with open(dist / 'index.js.map',  mode='r', encoding='utf-8') as file:
            index_js_map = file.read()

        return index_js + \
            f'\nScript.registerSourceMap("/index.js", `{index_js_map}`);\n' + \
            agent


DUMP_AGENT = '''\
Il2Cpp.perform(() => {
    for (const assembly of Il2Cpp.domain.assemblies) {
        send({ action: "dump", type: "assembly", value: assembly });
        for (const klass of assembly.image.classes) {
            send({ action: "dump", type: "class", value: klass });
        }
    }
}).then(_ => send({ action: "exit" }));
'''


if __name__ == "__main__":
    try:
        FridaIl2CppBridgeApplication().run()
    except KeyboardInterrupt:
        pass
