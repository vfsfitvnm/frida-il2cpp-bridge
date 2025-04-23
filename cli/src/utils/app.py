from __future__ import annotations
from typing import Any, override, Mapping
from abc import ABC, abstractmethod

import argparse
from frida_tools.application import ConsoleApplication, ConsoleState


class Application(ConsoleApplication):
    commands: dict[str, Command]
    options: argparse.Namespace

    @property
    def _selected_command(self) -> Command:
        return self.commands[self.options.command]

    def _add_commands(self, parser: argparse.ArgumentParser, **kwargs) -> None:
        subparsers = parser.add_subparsers(dest="command", required=True, **kwargs)

        for name, command in self.commands.items():
            subparser = subparsers.add_parser(name=name, **command.parser)
            command.add_arguments(subparser)

    @override
    def _initialize(
        self,
        parser: argparse.ArgumentParser,
        options: argparse.Namespace,
        args: list[str],
    ) -> None:
        self.options = options
        return super()._initialize(parser, options, args)

    def print(self, *args: Any, **kwargs: Any) -> None:
        return self._print(*args, **kwargs)

    def update_status(self, message: str) -> None:
        return self._update_status(message)

    def next_status(self) -> None:
        if self._console_state == ConsoleState.STATUS:
            self._print("", end="", flush=True)


class Command[
    T: "Application",
    SendPayload: Mapping[str, object],
    ExitPayload: Mapping[str, object],
](ABC):
    NAME: str

    def __init__(self, app: T):
        self.app = app

    @property
    @abstractmethod
    def agent_src(self) -> str:
        pass

    @property
    @abstractmethod
    def parser(self) -> dict:
        pass

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass

    @abstractmethod
    def on_send(self, payload: SendPayload) -> None:
        pass

    @abstractmethod
    def on_exit(self, payload: ExitPayload) -> None:
        pass
