from typing import override
from pathlib import Path
from sys import stdout


class refstr:
    def __init__(self):
        self.s = ""

    def __add__(self, s):
        self.s += s
        return self

    def __str__(self):
        return self.s


class TextSink:
    def write(self, text: str) -> None:
        pass

    def close(self) -> None:
        pass


class NopTextSink(TextSink):
    pass


class ConsoleTextSink(TextSink):
    @override
    def write(self, text: str) -> None:
        stdout.write(text)


class StrTextSink(TextSink):
    def __init__(self):
        self.s = ""

    @override
    def write(self, text: str) -> None:
        self.s += text


class FileTextSink(TextSink):
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(path, mode="w", encoding="utf-8")

    @override
    def write(self, text: str) -> None:
        self.file.write(text)

    @override
    def close(self) -> None:
        self.file.close()
