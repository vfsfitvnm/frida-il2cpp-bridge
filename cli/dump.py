from typing import TypedDict, Literal


class Assembly(TypedDict):
    name: str
    classCount: int


class Class(TypedDict):
    namespace: str | None
    name: str


class ClassDump(Class):
    handle: str


class AssemblyDump(Assembly):
    handle: str


class DumpPayload(TypedDict):
    type: Literal['assembly', 'class']
    value: AssemblyDump | ClassDump

    @property
    def assembly_dump(self) -> AssemblyDump | None:
        if self['type'] == 'assembly':
            return self.value

    @property
    def class_dump(self) -> ClassDump | None:
        if self['type'] == 'class':
            return self.value


class Dump:
    def __init__(self):
        self.assemblies: dict[str, Assembly] = {}
        self.classes: dict[str, Class] = {}

    def handle_payload(self, payload: DumpPayload) -> None:
        if payload['type'] == 'assembly':
            print(
                f'Dumping {payload['value']['name']} ({payload['value']['classCount']} classes)...')
        elif payload['type'] == 'class':
            pass
