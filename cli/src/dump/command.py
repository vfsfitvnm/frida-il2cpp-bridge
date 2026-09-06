from typing import override

import argparse
from textwrap import dedent
from pathlib import Path

import colorama

from ..app import FridaIl2CppBridgeCommand
from .dumper import Dumper
from .models import AssemblyHandle, ClassHandle, AssemblyDump, ClassDump


class DumpCommand(FridaIl2CppBridgeCommand[AssemblyDump | ClassDump, dict]):
    NAME = "dump"

    def __init__(self, *args, **kwargs):
        self._assemblies_dump: dict[AssemblyHandle, AssemblyDump] = {}
        self._classes_dump: dict[ClassHandle, ClassDump] = {}
        super().__init__(*args, **kwargs)

    @property
    def agent_src(self) -> str:
        with open(
            Path(__file__).parent / "agent.js", mode="r", encoding="utf-8"
        ) as file:
            return file.read()

    @property
    def parser(self) -> dict:
        return dict(
            help="performs a dump of the target application",
            formatter_class=argparse.RawTextHelpFormatter,
        )

    @override
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--out-dir",
            type=Path,
            default=Path.cwd(),
            help="where to save the dump (defaults to current working dir)",
        )
        parser.add_argument(
            "--cs-output",
            choices=["none", "stdout", "flat", "tree"],
            default="tree",
            help=dedent("""\
                style of C# output (defaults to tree)
                -   none: do nothing;
                - stdout: print to console;
                -   flat: one single file (dump.cs);
                -   tree: directory structure having one file per assembly.
                """),
        )
        parser.add_argument(
            "--no-namespaces",
            action="store_true",
            default=False,
            help=dedent("""\
                do not emit namespace blocks, and prepend namespace name in class declarations
                (without flag)          --no-namespaces
                namespace Foo           class Foo.Bar
                {                       {
                    class Bar               ...
                    {                   }
                        ...
                    }
                }
                """),
        )
        parser.add_argument(
            "--flatten-nested-classes",
            action="store_true",
            default=False,
            help=dedent("""\
                write nested classes at the same level of their inclosing classes, and prepend enclosing class name in their declarations
                (without flag)          --flatten-nested-classes
                class Foo               class Foo
                {                       {
                    ...                     ...
                                        }
                    class Bar
                    {                   class Foo.Bar
                        ...             {
                    }                       ...
                }                       }
                """),
        )
        parser.add_argument(
            "--keep-implicit-base-classes",
            action="store_true",
            default=False,
            help=dedent("""\
                write implicit base classes (class -> System.Object, struct -> System.ValueType, enum -> System.Enum) in class declarations
                (without flag)          --keep-implicit-base-classes
                class Foo               class Foo : System.Object
                {                       {
                }                       }

                struct Bar              struct Bar : System.ValueType
                {                       {
                }                       }
                
                enum Baz                enum Baz : System.Enum
                {                       {
                }                       }
                """),
        )
        parser.add_argument(
            "--enums-as-structs",
            action="store_true",
            default=False,
            help=dedent("""\
                write enum class declarations as structs
                (without flag)          --enums-as-structs
                enum Foo                struct Foo
                {                       {
                    First = 0,              int value__; // 0x10
                    Second = 1,             static Foo First = 0;
                }                           static Foo Second = 1;
                                        }
            """),
        )
        parser.add_argument(
            "--no-type-keywords",
            action="store_true",
            default=False,
            help=dedent("""\
                use fully qualified names for builtin types instead of their keywords
                (without flag)          --no-type-keywords
                class Foo               class Foo
                {                       {
                    int a;                  System.Int32 a;

                    void B(string c);       System.Void B(System.String c);
                }                       }
            """),
        )
        parser.add_argument(
            "--actual-constructor-names",
            action="store_true",
            default=False,
            help=dedent("""\
                write actual constructors names
                (without flag)          --no-type-keywords
                class Foo               class Foo
                {                       {
                    static Foo();           static void .cctor();

                    Foo();                  void .ctor();
                }                       }
            """),
        )
        parser.add_argument(
            "--indentation-size",
            type=int,
            default=4,
            help="indentation size (defaults to 4)",
        )

    @override
    def on_send(self, payload: AssemblyDump | ClassDump):
        if payload["type"] == "assembly":
            self._assemblies_dump[payload["handle"]] = payload
            assembly = self._assemblies_dump[payload["handle"]]
            self.app.next_status()
        elif payload["type"] == "class":
            self._classes_dump[payload["handle"]] = payload
            assembly = self._assemblies_dump[payload["assembly_handle"]]
        else:
            raise ValueError(f"Unknow dump type {payload}")

        self.app.update_status(
            f"Dumping {colorama.Fore.BLUE}{assembly['name']}{colorama.Fore.RESET}: {payload.get('nth', 1)} of {assembly['class_count']} classes"
        )

    @override
    def on_exit(self, payload: dict):
        self.app.print(
            f"Collected {colorama.Style.BRIGHT}{colorama.Fore.GREEN}{len(self._classes_dump)}{colorama.Style.RESET_ALL} classes in {payload['elapsed_ms'] / 1000:.2f}s"
        )

        if self.app.options.cs_output != "none":
            if self.app.options.cs_output != "stdout":
                self.app.update_status("Saving dump...")

            dumper = Dumper(
                assemblies_dump=self._assemblies_dump,
                classes_dump=self._classes_dump,
                output_base_path=self._output_base_path,
                config=Dumper.Config(
                    one_file_per_assembly=self.app.options.cs_output == "tree",
                    emit_namespaces=not self.app.options.no_namespaces,
                    flatten_nested_classes=self.app.options.flatten_nested_classes,
                    keep_implicit_base_classes=self.app.options.keep_implicit_base_classes,
                    enums_as_structs=self.app.options.enums_as_structs,
                    use_type_keywords=not self.app.options.no_type_keywords,
                    use_actual_constructor_names=self.app.options.actual_constructor_names,
                    indentation_size=self.app.options.indentation_size,
                ),
            )
            dumper.dump()

            if self.app.options.cs_output != "stdout":
                self.app.update_status(f"Dump saved to {dumper.output_base_path}")

    @property
    def _output_base_path(self) -> Path | None:
        if self.app.options.cs_output != "stdout":
            return (
                self.app.options.out_dir.resolve().absolute()
                / self.app.target["identifier"]
                / self.app.target["version"]
            )
        else:
            return None
