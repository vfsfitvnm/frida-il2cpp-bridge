from typing import Self
from dataclasses import dataclass

from itertools import zip_longest, groupby
from pathlib import Path

from ..utils.io import TextSink, ConsoleTextSink, FileTextSink, NopTextSink, refstr
from .models import (
    AssemblyHandle,
    ClassHandle,
    AssemblyDump,
    ClassDump,
    FieldDump,
    MethodDump,
)


class Dumper:
    @dataclass
    class Config:
        one_file_per_assembly: bool = True
        emit_namespaces: bool = True
        flatten_nested_classes: bool = False
        keep_implicit_base_classes: bool = False
        enums_as_structs: bool = False
        use_type_keywords: bool = True
        use_actual_constructor_names: bool = False
        indentation_size: int = 4

    BUILTIN_TYPE_TO_KEYWORD = {
        "System.Void": "void",
        "System.Boolean": "bool",
        "System.Byte": "byte",
        "System.SByte": "sbyte",
        "System.Char": "char",
        "System.Int16": "short",
        "System.UInt16": "ushort",
        "System.Int32": "int",
        "System.UInt32": "uint",
        "System.Int64": "long",
        "System.UInt64": "ulong",
        "System.IntPtr": "nint",
        "System.UIntPtr": "nuint",
        "System.Single": "float",
        "System.Double": "double",
        "System.Decimal": "decimal",
        "System.Object": "object",
        "System.String": "string",
    }

    BASE_TYPE_TO_KEYWORD = {
        "System.Object": "object",
        "System.ValueType": "struct",
        "System.Enum": "enum",
    }

    def __init__(
        self,
        assemblies_dump: dict[AssemblyHandle, AssemblyDump],
        classes_dump: dict[ClassHandle, ClassDump],
        output_base_path: Path | None,
        config: Config,
    ):
        self.assemblies_dump = assemblies_dump
        self.classes_dump = classes_dump
        self.output_base_path = output_base_path
        self.config = config
        self.output = IndentedTextWriter(
            sink=NopTextSink(),
            indentation_size=self.config.indentation_size,
        )

    def dump(self) -> None:
        if self.output_base_path is not None:
            if not self.config.one_file_per_assembly:
                self.output = IndentedTextWriter(
                    sink=FileTextSink(
                        path=(self.output_base_path / "dump").with_suffix(".cs")
                    ),
                    indentation_size=self.config.indentation_size,
                )
        else:
            self.output = IndentedTextWriter(
                sink=ConsoleTextSink(), indentation_size=self.config.indentation_size
            )

        for class_dump in self.classes_dump.values():
            if not self.config.flatten_nested_classes and (
                declaring_class_handle := class_dump.get("declaring_class_handle")
            ):
                declaring_class = self.classes_dump[declaring_class_handle]
                declaring_class["nested_classes_handles"] = (
                    declaring_class.get("nested_classes_handles") or []
                )
                declaring_class["nested_classes_handles"].append(class_dump["handle"])

            if self.config.enums_as_structs and class_dump["kind"] == "enum":
                class_dump["kind"] = "struct"

        for assembly_handle, classes_dump in groupby(
            sorted(self.classes_dump.values(), key=lambda _: _["assembly_handle"]),
            key=lambda _: _["assembly_handle"],
        ):
            require_new_line = False

            if self.config.one_file_per_assembly:
                self.output.close()

                if self.output_base_path:
                    self.output = IndentedTextWriter(
                        sink=FileTextSink(
                            path=(
                                self.output_base_path
                                / self.assemblies_dump[assembly_handle]["name"].replace(
                                    ".", "/"
                                )
                            ).with_suffix(".cs")
                        ),
                        indentation_size=self.config.indentation_size,
                    )
                else:
                    require_new_line = True

            current_namespace_parts = []

            for class_dump in classes_dump:
                if (
                    self.config.emit_namespaces
                    and "declaring_class_handle" not in class_dump
                ):
                    namespace_parts = (
                        class_dump["namespace"].split(".")
                        if class_dump.get("namespace")
                        else []
                    )

                    for i, (a, b) in enumerate(
                        zip_longest(namespace_parts, current_namespace_parts)
                    ):
                        if a != b:
                            for j in reversed(range(len(current_namespace_parts) - i)):
                                self.output.dedent().write("}")
                            if require_new_line:
                                require_new_line = False
                                self.output.ln()
                            for j in range(len(namespace_parts) - i):
                                self.output.write(
                                    f"namespace {namespace_parts[i + j]}"
                                ).write("{").indent()

                            current_namespace_parts = namespace_parts
                            break

                if (
                    not self.config.flatten_nested_classes
                    and class_dump.get("declaring_class_handle") is not None
                ):
                    continue

                if require_new_line:
                    self.output.ln()

                self._write_class(class_dump=class_dump)
                require_new_line = True

            for _ in range(len(current_namespace_parts)):
                self.output.dedent().write("}")

        self.output.close()

    def _write_class(self, class_dump: ClassDump) -> None:
        require_new_line = False

        if not self.config.one_file_per_assembly:
            with self.output as l:
                l += "// "
                l += self.assemblies_dump[class_dump["assembly_handle"]]["name"]

        with self.output as l:
            l += class_dump["kind"]
            l += " "
            l += self._class_name(class_dump)
            if parent_type_name := class_dump.get("parent_type_name"):
                if (
                    not self.config.keep_implicit_base_classes
                    and parent_type_name in self.BASE_TYPE_TO_KEYWORD
                ):
                    parent_type_name = None
                else:
                    l += " : "
                    l += self._type_name(parent_type_name)
            if interfaces_type_names := class_dump.get("interfaces_type_names"):
                l += ", " if parent_type_name else " : "
                for i, interface_type_name in enumerate(interfaces_type_names):
                    l += ", " if i > 0 else ""
                    l += self._type_name(interface_type_name)

        self.output.write("{").indent()

        fields = class_dump.get("fields") or []
        literal_fields = [_ for _ in fields if _["is_literal"]]
        static_fields = [
            _
            for _ in fields
            if _["is_static"] and not _["is_thread_static"] and not _["is_literal"]
        ]
        thread_static_fields = [_ for _ in fields if _["is_thread_static"]]
        instance_fields = [_ for _ in fields if not _["is_static"]]

        methods = class_dump.get("methods") or []
        static_methods = sorted(
            [_ for _ in methods if _["is_static"]],
            key=lambda _: _["name"] == ".cctor",
            reverse=True,
        )
        instance_methods = sorted(
            [_ for _ in methods if not _["is_static"]],
            key=lambda _: _["name"] == ".ctor",
            reverse=True,
        )

        for field_group in [
            literal_fields,
            static_fields,
            thread_static_fields,
            instance_fields,
        ]:
            require_new_line = require_new_line or len(field_group) > 0
            for field_dump in field_group:
                if class_dump["kind"] == "enum":
                    self._write_enum_field(field_dump=field_dump)
                else:
                    self._write_field(field_dump=field_dump)

        if require_new_line and methods:
            require_new_line = False
            self.output.ln()

        for method_group in [static_methods, instance_methods]:
            require_new_line = require_new_line or len(method_group) > 0
            for method_dump in method_group:
                self._write_method(
                    method_dump=method_dump, declared_in_class_dump=class_dump
                )

        if require_new_line and class_dump.get("nested_classes_handles"):
            require_new_line = False
            self.output.ln()

        for i, nested_class_handle in enumerate(
            class_dump.get("nested_classes_handles") or []
        ):
            if i > 0:
                self.output.ln()
            self._write_class(self.classes_dump[nested_class_handle])

        self.output.dedent().write("}")

    def _write_field(self, field_dump: FieldDump):
        with self.output as l:
            if field_dump["is_thread_static"]:
                l += "[ThreadStatic] "
            if field_dump["is_static"]:
                l += "static "
            if (offset := field_dump.get("offset")) is not None:
                l += "/*"
                l += hex(offset)
                l += "*/ "
            l += self._type_name(field_dump["type_name"])
            l += " "
            l += field_dump["name"]
            if (value := field_dump.get("value", None)) is not None:
                l += " = "
                l += str(value)
            l += ";"

    def _write_enum_field(self, field_dump: FieldDump):
        if not field_dump["is_static"]:
            return
        with self.output as l:
            l += field_dump["name"]
            if (value := field_dump.get("value", None)) is not None:
                l += " = "
                l += str(value)
            l += ","

    def _write_method(self, method_dump: MethodDump, declared_in_class_dump: ClassDump):
        with self.output as l:
            if method_dump["is_static"]:
                l += "static "
            if (offset := method_dump.get("offset")) is not None:
                l += "/*"
                l += offset.lower()
                l += "*/ "
            if not self.config.use_actual_constructor_names and (
                method_dump["name"] == ".ctor" or method_dump["name"] == ".cctor"
            ):
                l += self._constructor_name(declared_in_class_dump)
            else:
                l += self._type_name(method_dump["return_type_name"])
                l += " "
                l += method_dump["name"]
            if generics_type_names := method_dump.get("generics_type_names"):
                l += "<"
                for i, generic_type_name in enumerate(generics_type_names):
                    l += ", " if i > 0 else ""
                    l += self._type_name(generic_type_name)
                l += ">"
            l += "("
            for i, param in enumerate(
                sorted(method_dump.get("parameters", []), key=lambda _: _["position"])
            ):
                l += ", " if i > 0 else ""
                l += self._type_name(param["type_name"])
                l += " "
                l += param["name"]
            l += ");"

    def _class_name(
        self,
        class_dump_or_handle: str | ClassDump,
        include_namespace_name: bool | None = None,
        include_declaring_class_name: bool | None = None,
    ) -> str:
        if isinstance(class_dump_or_handle, str):
            try:
                class_dump = self.classes_dump[class_dump_or_handle]
            except KeyError:
                return "__MISSING__"
        else:
            class_dump = class_dump_or_handle

        if include_namespace_name is None:
            include_namespace_name = not self.config.emit_namespaces

        if include_declaring_class_name is None:
            include_declaring_class_name = self.config.flatten_nested_classes

        s = ""

        if include_namespace_name and (namespace := class_dump.get("namespace")):
            s += namespace + "."

        if include_declaring_class_name and (
            declaring_class_handle := class_dump.get("declaring_class_handle")
        ):
            s += (
                self._class_name(
                    class_dump_or_handle=self.classes_dump[declaring_class_handle],
                    include_namespace_name=include_namespace_name,
                    include_declaring_class_name=include_declaring_class_name,
                )
                + "."
            )

        s += class_dump["name"]

        if generics_type_names := class_dump.get("generics_type_names"):
            s = (
                s.rstrip("`" + str(len(generics_type_names)))
                + "<"
                + ", ".join(generics_type_names)
                + ">"
            )

        return s

    def _constructor_name(self, class_dump: ClassDump) -> str:
        if generics_type_names := class_dump.get("generics_type_names"):
            return class_dump["name"].rstrip("`" + str(len(generics_type_names)))
        else:
            return class_dump["name"]

    def _type_name(self, type_name: str) -> str:
        if self.config.use_type_keywords:
            type_name = TypeNameCleaner.replace_known_types(
                type_name, self.BUILTIN_TYPE_TO_KEYWORD
            )
            type_name = TypeNameCleaner.add_ref_keyword_for_reference_types(type_name)
        type_name = TypeNameCleaner.add_space_after_comma_in_generic_parameters(
            type_name
        )
        return type_name


class TypeNameCleaner:
    @staticmethod
    def add_ref_keyword_for_reference_types(type_name: str) -> str:
        return "ref " + type_name[:-1] if type_name.endswith("&") else type_name

    @staticmethod
    def add_space_after_comma_in_generic_parameters(type_name: str) -> str:
        try:
            start = type_name.index("<")
            end = type_name.rindex(">")
            return type_name[:start] + type_name[start : end + 1].replace(
                ", ", ","
            ).replace(",", ", ")
        except ValueError:
            return type_name

    @staticmethod
    def replace_known_types(type_name: str, mapping: dict[str, str]) -> str:
        for name, replacement in mapping.items():
            if type_name == name:
                return replacement

            for char in [">", ",", "*"]:
                type_name = type_name.replace(name + char, replacement + char)

            if type_name == name + "&":
                return replacement + "&"
            elif type_name.startswith(name + "["):
                return replacement + type_name[len(name) :]

        return type_name


class IndentedTextWriter:
    def __init__(
        self,
        sink: TextSink,
        indentation_size: int = 4,
    ):
        self.sink = sink
        self.indentation_size = indentation_size
        self.indentation_level = 0

        self._context_buf = refstr()

    def indent(self) -> Self:
        self.indentation_level += 1
        return self

    def dedent(self) -> Self:
        self.indentation_level -= 1
        return self

    def ln(self) -> Self:
        self.sink.write("\n")
        return self

    def write(self, text: str) -> Self:
        self.sink.write(
            " " * self.indentation_size * self.indentation_level + text + "\n"
        )
        return self

    def close(self) -> None:
        self.sink.close()

    def __enter__(self) -> refstr:
        return self._context_buf

    def __exit__(self, *_) -> None:
        text = self._context_buf.s
        self._context_buf = refstr()
        self.write(text)
