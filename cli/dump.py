from typing import TypedDict, Literal, Any, Optional, Union
from textwrap import dedent


class Assembly(TypedDict):
    name: str
    classCount: int


class Field(TypedDict):
    name: str
    type: str
    threadStatic: bool
    static: bool
    literal: bool
    value: Any
    offset: Optional[int]


class Parameter(TypedDict):
    name: str
    type: str
    position: int


class Method(TypedDict):
    name: str
    static: bool
    returnType: str
    parameters: list[Parameter]
    offset: Optional[str]


class Class(TypedDict):
    assembly: str
    namespace: Optional[str]
    name: str
    kind: Literal['enum', 'struct', 'interface', 'class']
    parent: Optional[str]
    declaredIn: Optional[str]
    generics: Optional[list[str]]
    interfaces: Optional[list[str]]
    fields: list[Field]
    methods: list[Method]


class ClassDump(Class):
    handle: str


class AssemblyDump(Assembly):
    handle: str


class DumpPayload(TypedDict):
    type: Literal['assembly', 'class']
    value: Union[AssemblyDump, ClassDump]

    @property
    def assembly_dump(self) -> Optional[AssemblyDump]:
        if self['type'] == 'assembly':
            return self.value

    @property
    def class_dump(self) -> Optional[ClassDump]:
        if self['type'] == 'class':
            return self.value


class Dump:
    def __init__(self, output: Literal['none', 'flat', 'tree']):
        self.output = output
        self.assemblies: dict[str, AssemblyDump] = {}
        self.classes: dict[str, ClassDump] = {}

    def handle_payload(self, dump_payload: DumpPayload) -> None:
        if assembly_dump := dump_payload.assembly_dump:
            self.assemblies[assembly_dump['handle']] = assembly_dump
        elif class_dump := dump_payload.class_dump:
            self.classes[class_dump['handle']] = class_dump

    def class_to_cs(self, klass: Class) -> str:
        return f'{klass["kind"]} {klass["name"]}'


DUMP_AGENT = '''
Il2Cpp.perform(() => {
    send({ action: "init" });
    send({ action: "application", value: { id: Il2Cpp.application.identifier, version: Il2Cpp.application.version }});
    for (const assembly of Il2Cpp.domain.assemblies) {
        send({ action: "dump", type: "assembly", value: assembly });
        for (const klass of assembly.image.classes) {
            send({ action: "dump", type: "class", value: klass });
        }
    }
}).then(_ => send({ action: "exit" }));
'''
