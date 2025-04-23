from __future__ import annotations
from typing import TypedDict, Literal, Any


type AssemblyHandle = str


type ClassHandle = str


class AssemblyDump(TypedDict):
    type: Literal["assembly"]
    handle: AssemblyHandle
    name: str
    class_count: int


class ClassDump(TypedDict):
    type: Literal["class"]
    assembly_handle: AssemblyHandle
    handle: ClassHandle
    declaring_class_handle: ClassHandle
    namespace: str | None
    name: str
    generics_type_names: list[str]
    kind: Literal["enum", "struct", "interface", "class"]
    parent_type_name: str
    interfaces_type_names: list[str]
    fields: list[FieldDump]
    methods: list[MethodDump]
    nested_classes_handles: list[ClassHandle] | None


class FieldDump(TypedDict):
    name: str
    type_name: str
    is_thread_static: bool
    is_static: bool
    is_literal: bool
    value: Any
    offset: int | None


class MethodDump(TypedDict):
    name: str
    is_static: bool
    generics_type_names: list[str]
    return_type_name: str
    parameters: list[ParameterDump]
    offset: str | None


class ParameterDump(TypedDict):
    name: str
    type_name: str
    position: int
