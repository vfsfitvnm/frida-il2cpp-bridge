# frida-il2cpp-bridge

[![Frida](https://img.shields.io/badge/-frida-ef6456?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyAgIHZlcnNpb249IjEuMSIgICBpZD0iTGF5ZXJfMSIgICB4PSIwcHgiICAgeT0iMHB4IiAgIHZpZXdCb3g9IjAgMCA5LjcyOTk3OTkgMTAuOTM1NzEyIiAgIGVuYWJsZS1iYWNrZ3JvdW5kPSJuZXcgMCAwIDIwNC40IDM5IiAgIHhtbDpzcGFjZT0icHJlc2VydmUiICAgc29kaXBvZGk6ZG9jbmFtZT0ibG9nby5zdmciICAgd2lkdGg9IjkuNzI5OTc5NSIgICBoZWlnaHQ9IjEwLjkzNTcxMiIgICBpbmtzY2FwZTp2ZXJzaW9uPSIxLjEgKGNlNjY2M2IzYjcsIDIwMjEtMDUtMjUpIiAgIHhtbG5zOmlua3NjYXBlPSJodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy9uYW1lc3BhY2VzL2lua3NjYXBlIiAgIHhtbG5zOnNvZGlwb2RpPSJodHRwOi8vc29kaXBvZGkuc291cmNlZm9yZ2UubmV0L0RURC9zb2RpcG9kaS0wLmR0ZCIgICB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnMgICBpZD0iZGVmczkiIC8+PHNvZGlwb2RpOm5hbWVkdmlldyAgIGlkPSJuYW1lZHZpZXc3IiAgIHBhZ2Vjb2xvcj0iI2ZmZmZmZiIgICBib3JkZXJjb2xvcj0iIzY2NjY2NiIgICBib3JkZXJvcGFjaXR5PSIxLjAiICAgaW5rc2NhcGU6cGFnZXNoYWRvdz0iMiIgICBpbmtzY2FwZTpwYWdlb3BhY2l0eT0iMC4wIiAgIGlua3NjYXBlOnBhZ2VjaGVja2VyYm9hcmQ9IjAiICAgc2hvd2dyaWQ9ImZhbHNlIiAgIGZpdC1tYXJnaW4tdG9wPSIwIiAgIGZpdC1tYXJnaW4tbGVmdD0iMCIgICBmaXQtbWFyZ2luLXJpZ2h0PSIwIiAgIGZpdC1tYXJnaW4tYm90dG9tPSIwIiAgIGlua3NjYXBlOnpvb209IjYuOTE3ODA4NCIgICBpbmtzY2FwZTpjeD0iLTAuMTQ0NTU0NDUiICAgaW5rc2NhcGU6Y3k9Ii04LjYwMDk4OTkiICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxOTIwIiAgIGlua3NjYXBlOndpbmRvdy1oZWlnaHQ9IjEwMDgiICAgaW5rc2NhcGU6d2luZG93LXg9IjAiICAgaW5rc2NhcGU6d2luZG93LXk9IjAiICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSIgICBpbmtzY2FwZTpjdXJyZW50LWxheWVyPSJMYXllcl8xIiAvPjxnICAgaWQ9Imc0IiAgIHN0eWxlPSJkaXNwbGF5OmlubGluZTtmaWxsOiNmZmZmZmYiICAgdHJhbnNmb3JtPSJtYXRyaXgoMC4yODA0MDI4NiwwLDAsMC4yODA0MDI4NiwtMTEuNTgwNjM4LDApIj48cGF0aCAgIGZpbGw9IiNmZmZmZmYiICAgZD0iTSA1MS40LDM5IEggNDEuMyBMIDQ5LjcsMjYuMSBDIDQ0LjksMjMuOCA0Mi4zLDE5LjYgNDIuMywxMy41IDQyLjMsNC44IDQ4LjIsMCA1OC41LDAgSCA3NiBWIDM5IEggNjcgViAyOCBIIDU4LjUgNTcuNyBaIE0gNjcsMjAgViA3IGggLTguNSBjIC00LjksMCAtNy43LDIgLTcuNyw2LjQgMCw0LjUgMi44LDYuNiA3LjcsNi42IHoiICAgaWQ9InBhdGgyIiAgIHN0eWxlPSJmaWxsOiNmZmZmZmYiIC8+PC9nPjwvc3ZnPg==)](https://frida.re)
[![NPM](https://img.shields.io/npm/v/frida-il2cpp-bridge?label=&logo=npm&style=for-the-badge)](https://npmjs.org/package/frida-il2cpp-bridge)

A Frida module to dump, trace or hijack any Il2Cpp application at runtime, without needing the `global-metadata.dat` file.

![code](https://github.com/vfsfitvnm/frida-il2cpp-bridge/assets/46219656/d8e81811-b98c-4d67-9cea-be8cab8947ef)

## Features

-   Dump classes, methods, fields and so on
-   Trace, intercept and replace method calls
-   Mess around with the C# runtime
-   Il2Cpp structs and global metadata (almost) free

## Compatibility

#### Unity version

It should work for any Unity version in the range **5.3.0** - **6000.1.x**.

#### Platforms

**Android**, **Linux**, **Windows**, **iOS**, **macOS** are supported.
However, only Android and Linux are "tested": expect breakage if you are using another platform.

## CLI

Starting from version `0.10.0`, a `frida-il2cpp-bridge` Python executable is included alongside the NPM package installation. This executable wraps the `frida` command and adds IL2CPP specific features. To invoke it, simply run:

```sh
npx frida-il2cpp-bridge --help
```

or

```sh
npm exec frida-il2cpp-bridge -- --help
```

### Dumping

Use the `dump` subcommand to dump an application:

```
$ npm exec frida-il2cpp-bridge -- dump --help
usage: frida-il2cpp-bridge [options] dump [-h] [--out-dir OUT_DIR] [--cs-output {none,stdout,flat,tree}] [--no-namespaces] [--flatten-nested-classes] [--keep-implicit-base-classes]
                                          [--enums-as-structs] [--no-type-keywords] [--actual-constructor-names] [--indentation-size INDENTATION_SIZE]

options:
  -h, --help            show this help message and exit
  --out-dir OUT_DIR     where to save the dump (defaults to current working dir)
  --cs-output {none,stdout,flat,tree}
                        style of C# output (defaults to tree)
                        -   none: do nothing;
                        - stdout: print to console;
                        -   flat: one single file (dump.cs);
                        -   tree: directory structure having one file per assembly.
  --no-namespaces       do not emit namespace blocks, and prepend namespace name in class declarations
  --flatten-nested-classes
                        write nested classes at the same level of their inclosing classes, and prepend enclosing class name in their declarations
  --keep-implicit-base-classes
                        write implicit base classes (class -> System.Object, struct -> System.ValueType, enum -> System.Enum) in class declarations
  --enums-as-structs    write enum class declarations as structs
  --no-type-keywords    use fully qualified names for builtin types instead of their keywords (e.g. use 'System.Int32' instead of 'int', or 'System.Object' instead of 'object')
  --actual-constructor-names
                        write actual constructors names (e.g. '.ctor' and '.cctor')
  --indentation-size INDENTATION_SIZE
                        indentation size (defaults to 4)
```

Example:

```sh
npm exec frida-il2cpp-bridge -- -f com.example.application dump --out-dir dumps
```

Output:

```
Spawning `com.example.application`...
IL2CPP module loaded in 1.13s (id=com.example.application, version=1.12.8, unity version=2019.3.0f1)
Dumping mscorlib: 2872 of 2872 classes
Dumping GameAssembly: 32 of 32 classes
Collected 2904 classes in 4.76s
Dump saved to dumps/com.example.application/1.12.8
```

## Testing

Over the time, it was realized that some testing was necessary, as supporting many Unity version makes introducing regressions or faulty features easy. Though it's far from being complete and bullet-proof, there's a minimal testing setup contributors can get advantage of to test their changes. \
In order to test `frida-il2cpp-bridge`, a IL2CPP application is needed (of course). Here are some very useful resources:

-   [IL2CPP toolchain](https://katyscode.wordpress.com/2020/06/24/il2cpp-part-1/)
-   [Scripting](https://github.com/djkaty/Il2CppInspector/blob/116c6355e7ee3656eab85ca753f913d428abc7a3/Il2CppTests/il2cpp.ps1)

### Commands

Unity editors (so IL2CPP toolchains) will be downloaded and extracted automatically.

**Prerequisites**

1. Only Linux is currently supported;
2. Make sure to have `clang` and `make` installed.

#### Build IL2CPP assemblies

```sh
make assemblies
```

An assembly (`GameAssembly.so`) will be built for each of [tested Unity versions](https://github.com/vfsfitvnm/frida-il2cpp-bridge/tree/master/unity).

#### Build IL2CPP assembly for a specific Unity version only

```sh
make unity/2019.3.0f1/
```

#### Run tests

```sh
make test
```

Tests run against only the installed Unity versions.

## Acknowledgements

Thanks to [meme](https://github.com/meme) and [knobse](https://github.com/knobse) for helping and getting me into this,
and to [djkaty](https://github.com/djkaty) and [nneonneo](https://github.com/nneonneo) for providing the Il2Cpp
API.

## Problems?

Discussions and Wiki are both active. Use them!
