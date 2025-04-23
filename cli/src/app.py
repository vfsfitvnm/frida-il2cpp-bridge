from __future__ import annotations
from typing import Mapping, TypedDict, override

import argparse
from pathlib import Path
import colorama
import frida
from frida.core import ScriptMessage

from .utils.app import Application, Command
from . import NPM_MODULE_PATH, __name__, __version__


class FridaIl2CppBridgeApplication(Application):
    class Target(TypedDict):
        identifier: str
        version: str

    def __init__(self, commands: list[type[FridaIl2CppBridgeCommand]]) -> None:
        self.commands = {command.NAME: command(app=self) for command in commands}
        self.target: FridaIl2CppBridgeApplication.Target
        self._script = None

        super().__init__()

    @override
    def _needs_target(self) -> bool:
        return True

    @override
    def _initialize_arguments_parser(self) -> argparse.ArgumentParser:
        parser = super()._initialize_arguments_parser()
        for action in parser._actions:
            if isinstance(action, argparse._VersionAction) and action.dest == "version":
                action.version = (
                    f"{frida.__name__}: {action.version} | {__name__}: {__version__}"
                )
        return parser

    @override
    def _add_options(self, parser: argparse.ArgumentParser) -> None:
        group = parser.add_argument_group(title="IL2CPP options")
        group.add_argument(
            "--unity-version",
            required=False,
            help="Unity version in case it cannot be detected automatically",
        )
        group.add_argument(
            "--module-name",
            required=False,
            help="IL2CPP module name in case it cannot be detected automatically",
        )
        group.add_argument(
            "--script-prelude",
            required=False,
            type=Path,
            help="path to .js script to be executed before running command-specific code",
        )

        self._add_commands(parser, description="IL2CPP specific commands")

    @override
    def _start(self) -> None:
        if agent_src := self._selected_command.agent_src:
            assert self._session is not None

            script = self._session.create_script(
                name="index",
                source=self._script_prelude() + agent_src,
                runtime=self._runtime,
            )

            script.on(
                "message",
                lambda message, data: self._reactor.schedule(
                    lambda: self._process_message(message, data)
                ),
            )

            script.load()

            self._script = script
        else:
            self._script = None

        self._resume()

    @override
    def _stop(self) -> None:
        if self._script:
            self._script.unload()
            self._script = None

    def _process_message(self, message: ScriptMessage, _) -> None:
        if message["type"] == "send" and (payload := message.get("payload")):
            match payload.get("action"):
                case "init":
                    self.target = payload["application"]
                    self.next_status()
                    self.update_status(
                        f"IL2CPP module loaded in {payload['elapsed_ms'] / 1000:.2f}s (id={colorama.Style.BRIGHT}{colorama.Fore.MAGENTA}{self.target['identifier']}{colorama.Fore.RESET}, version={colorama.Style.BRIGHT}{colorama.Fore.MAGENTA}{self.target['version']}{colorama.Fore.RESET}, unity version={colorama.Style.BRIGHT}{colorama.Fore.YELLOW}{payload['unityVersion']}{colorama.Fore.RESET})"
                    )
                case "exit":
                    self._selected_command.on_exit(payload=payload)
                    self._exit(0)
                case None:
                    self._selected_command.on_send(payload=payload)
                case action:
                    raise ValueError(f"Unknown payload action {action}")
        elif message["type"] == "error":
            self._log("error", message.get("stack", message["description"]))
            self._exit(1)

    def _script_prelude(self) -> str:
        dist = NPM_MODULE_PATH / "dist"

        with open(dist / "index.js", mode="r", encoding="utf-8") as file:
            src = file.read() + "\n"

        with open(dist / "index.js.map", mode="r", encoding="utf-8") as file:
            src += f'Script.registerSourceMap("/index.js", `{file.read()}`);\n'

        if unity_version := self.options.unity_version:
            src += f'globalThis.IL2CPP_UNITY_VERSION = "{unity_version}";\n'

        if module_name := self.options.module_name:
            src += f'globalThis.IL2CPP_MODULE_NAME = "{module_name}";\n'

        if script_prelude := self.options.script_prelude:
            with open(script_prelude.resolve(), mode="r", encoding="utf-8") as file:
                src += file.read() + "\n"

        return src


class FridaIl2CppBridgeCommand[
    SendPayload: Mapping[str, object],
    ExitPayload: Mapping[str, object],
](Command[FridaIl2CppBridgeApplication, SendPayload, ExitPayload]):
    pass
