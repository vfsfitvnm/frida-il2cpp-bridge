# frida-il2cpp-bridge

[![Frida](https://img.shields.io/badge/-frida-ef6456?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyAgIHZlcnNpb249IjEuMSIgICBpZD0iTGF5ZXJfMSIgICB4PSIwcHgiICAgeT0iMHB4IiAgIHZpZXdCb3g9IjAgMCA5LjcyOTk3OTkgMTAuOTM1NzEyIiAgIGVuYWJsZS1iYWNrZ3JvdW5kPSJuZXcgMCAwIDIwNC40IDM5IiAgIHhtbDpzcGFjZT0icHJlc2VydmUiICAgc29kaXBvZGk6ZG9jbmFtZT0ibG9nby5zdmciICAgd2lkdGg9IjkuNzI5OTc5NSIgICBoZWlnaHQ9IjEwLjkzNTcxMiIgICBpbmtzY2FwZTp2ZXJzaW9uPSIxLjEgKGNlNjY2M2IzYjcsIDIwMjEtMDUtMjUpIiAgIHhtbG5zOmlua3NjYXBlPSJodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy9uYW1lc3BhY2VzL2lua3NjYXBlIiAgIHhtbG5zOnNvZGlwb2RpPSJodHRwOi8vc29kaXBvZGkuc291cmNlZm9yZ2UubmV0L0RURC9zb2RpcG9kaS0wLmR0ZCIgICB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnMgICBpZD0iZGVmczkiIC8+PHNvZGlwb2RpOm5hbWVkdmlldyAgIGlkPSJuYW1lZHZpZXc3IiAgIHBhZ2Vjb2xvcj0iI2ZmZmZmZiIgICBib3JkZXJjb2xvcj0iIzY2NjY2NiIgICBib3JkZXJvcGFjaXR5PSIxLjAiICAgaW5rc2NhcGU6cGFnZXNoYWRvdz0iMiIgICBpbmtzY2FwZTpwYWdlb3BhY2l0eT0iMC4wIiAgIGlua3NjYXBlOnBhZ2VjaGVja2VyYm9hcmQ9IjAiICAgc2hvd2dyaWQ9ImZhbHNlIiAgIGZpdC1tYXJnaW4tdG9wPSIwIiAgIGZpdC1tYXJnaW4tbGVmdD0iMCIgICBmaXQtbWFyZ2luLXJpZ2h0PSIwIiAgIGZpdC1tYXJnaW4tYm90dG9tPSIwIiAgIGlua3NjYXBlOnpvb209IjYuOTE3ODA4NCIgICBpbmtzY2FwZTpjeD0iLTAuMTQ0NTU0NDUiICAgaW5rc2NhcGU6Y3k9Ii04LjYwMDk4OTkiICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxOTIwIiAgIGlua3NjYXBlOndpbmRvdy1oZWlnaHQ9IjEwMDgiICAgaW5rc2NhcGU6d2luZG93LXg9IjAiICAgaW5rc2NhcGU6d2luZG93LXk9IjAiICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSIgICBpbmtzY2FwZTpjdXJyZW50LWxheWVyPSJMYXllcl8xIiAvPjxnICAgaWQ9Imc0IiAgIHN0eWxlPSJkaXNwbGF5OmlubGluZTtmaWxsOiNmZmZmZmYiICAgdHJhbnNmb3JtPSJtYXRyaXgoMC4yODA0MDI4NiwwLDAsMC4yODA0MDI4NiwtMTEuNTgwNjM4LDApIj48cGF0aCAgIGZpbGw9IiNmZmZmZmYiICAgZD0iTSA1MS40LDM5IEggNDEuMyBMIDQ5LjcsMjYuMSBDIDQ0LjksMjMuOCA0Mi4zLDE5LjYgNDIuMywxMy41IDQyLjMsNC44IDQ4LjIsMCA1OC41LDAgSCA3NiBWIDM5IEggNjcgViAyOCBIIDU4LjUgNTcuNyBaIE0gNjcsMjAgViA3IGggLTguNSBjIC00LjksMCAtNy43LDIgLTcuNyw2LjQgMCw0LjUgMi44LDYuNiA3LjcsNi42IHoiICAgaWQ9InBhdGgyIiAgIHN0eWxlPSJmaWxsOiNmZmZmZmYiIC8+PC9nPjwvc3ZnPg==)](https://frida.re)
[![NPM](https://img.shields.io/npm/v/frida-il2cpp-bridge?label=&logo=npm&style=for-the-badge)](https://npmjs.org/package/frida-il2cpp-bridge)

A Frida module to dump, trace or hijack any Il2Cpp application at runtime, without needing the `global-metadata.dat` file.

![Screenshot_20210724_195807](https://user-images.githubusercontent.com/46219656/126877297-97529b9b-e74b-4130-9b6e-061b938a5737.png)
## Compatibility

#### Unity version
It should work for any Unity version in the inclusive range **5.3.0** - **2021.1.0**.

#### Platforms
**Android** is supported; **Linux** and **Windows** are not tested; **iOS** is not supported yet 
([#15](https://github.com/vfsfitvnm/frida-il2cpp-bridge/issues/15)).

## Acknowledgements
Thanks to [meme](https://github.com/meme) and [tryso](https://github.com/tryso) for helping and getting me into this, 
and to [djkaty](https://github.com/djkaty) and [nneonneo](https://github.com/nneonneo) for providing the IL2CPP C
headers.

# Documentation

### Table of contents

* [Project setup](#project-setup)
    * [From scratch](#from-scratch)
    * [Existing project](#existing-project)
* [Snippets](#snippets)
    * [Initialization](#initialization)
    * [Dump](#dump)
    * [Trace](#trace)
    * [Heap scan](#heap-scan)
    * [Methods](#methods)
        * [Invocation](#invocation)
        * [Replacement & Interception](#replacement--interception)
    * [Generics handling](#generics-handling)
* [Miscellaneous](#miscellaneous)
    * [How to handle overloading](#how-to-handle-overloading)
    * [Ghidra script](#ghidra-script)

---

## Project setup

### From scratch

This is a Frida TypeScript module, so it follows any other TypeScript (`npm`) project:

```
└── project
    ├── index.ts
    ├── packages.json
    └── tsconfig.json
```

This is how it should looke like:

**index.ts** \
This is where you write the code. More info [here](#initialization).

```ts
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    // code here
});
```

**packages.json** \
This is where you can declare scripts (commands to execute) and dependencies. \
`frida-compile` packs and transpile a multi file project with its dependencies into a single plain JavaScript file
(its name is `_.js` here). \
Learn more about `packages.json` [here](https://docs.npmjs.com/cli/v7/configuring-npm/package-json).

```json
{
  "name": "project",
  "main": "index.ts",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "build": "frida-compile -o _.js -w index.ts",
    "attach": "run() { frida -U \"$1\" -l _.js --runtime=v8; }; run",
    "spawn": "run() { frida -U -f \"$1\" -l _.js --no-pause --runtime=v8; }; run",
    "app0-spawn": "npm run spawn com.example.application0",
    "app1": "npm run \"Application1 Name\"",
    "app1-spawn": "npm run spawn com.example.application1"
  },
  "devDependencies": {
    "@types/frida-gum": "^17.1.0",
    "frida-compile": "^10.2.4",
    "frida-il2cpp-bridge": "^0.5.1"
  }
}
```

**tsconfig.json** \
You can just copy and paste this. \
Learn more about `tsconfig.json` [here](https://www.typescriptlang.org/docs/handbook/tsconfig-json.html).

```json
{
  "compilerOptions": {
    "target": "es2020",
    "lib": [
      "es2020"
    ],
    "allowJs": true,
    "noEmit": true,
    "strict": true,
    "esModuleInterop": true,
    "experimentalDecorators": true,
    "moduleResolution": "node"
  }
}
```

### Existing project

If you just want to add this module to an already existing project:

```shell script
$ npm install --save-dev frida-il2cpp-bridge
```

You may need to add `"moduleResolution": "node"` in your `tsconfig.json` under `compilerOptions`.

---

## Snippets

Consider contribute or opening an issue, if you think something is missing.

### Initialization

```ts
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    // code here
});
```

You import the global `Il2Cpp` object in the following way. \
Before executing any `Il2Cpp` operation, the caller thread *should* be attached to the application domain; after the
execution, it *should* be detached. I said "*should*" because it's not mandatory, however you can bump into some abort
or access violation errors if you skip this step. \
You can ensure this behaviour wrapping your code inside a `Il2Cpp.perform` function - this wrapper also ensures any
initialization process has finished. Given so, this function is asynchronous because it may need to wait for Il2Cpp
module to load and initialize (`il2cpp_init`).

### Dump

```ts
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    // it will use default directory path and file name: /<default_path>/<default_name>.cs
    Il2Cpp.Dumper.classicDump();

    // the file name is overridden: /<default_path>/custom_file_name.cs
    Il2Cpp.Dumper.classicDump("custom_file_name");

    // the file name and directory path are overridden: /i/can/write/to/this/path/custom_file_name.cs
    Il2Cpp.Dumper.classicDump("custom_file_name", "/i/can/write/to/this/path");

    // alternatively
    Il2Cpp.Dumper.snapshotDump();
});
```

There are two already defined strategies you can follow in order to dump the application. \
The **first one**, the _classic dump_, iterates all the assemblies, and then dump all the classes inside them. This
strategy is pretty straightforward, however it misses quite few classes (array and inflated classes - `System.String[]`
and
`System.Collections.Generic.List<System.String>` for instance). These _missing_ classes do not contain any "hidden"
code, however they may be useful during static analysis. \
The **second one**, the _snapshot dump_, comes to the rescue. It performs a memory snapshot
(IL2CPP generously exposes the APIs), which also includes the classes the classic dump could not easily guess,
thankfully. However, the snapshot only reports already initialized classes: it's important to run this dump as late as
possible. The second dump seems to include the same classes the first one would find.

Dumping may require two parameters: a directory path (e.g. a place where the application can write to) and a file name.
If not provided, the code will just guess them; however it might fail on some applications and/or Unity versions.

The dump will produce the following output:

```cs
// mscorlib.dll
struct System.Int32 : System.ValueType, System.IFormattable, System.IConvertible, System.IComparable, System.IComparable<System.Int32>, System.IEquatable<System.Int32>
{
    static System.Int32 MaxValue = 2147483647;
    static System.Int32 MinValue = -2147483648;
    System.Int32 m_value; // 0x10

    System.Boolean System.IConvertible.ToBoolean(System.IFormatProvider provider); // 0x00bed724
    System.Byte System.IConvertible.ToByte(System.IFormatProvider provider); // 0x00bed72c
    System.Char System.IConvertible.ToChar(System.IFormatProvider provider); // 0x00bed734
    System.DateTime System.IConvertible.ToDateTime(System.IFormatProvider provider); // 0x00bed73c
    System.Decimal System.IConvertible.ToDecimal(System.IFormatProvider provider); // 0x00bed744
    System.Double System.IConvertible.ToDouble(System.IFormatProvider provider); // 0x00bed74c
    // ...
}

// ...
```

### Trace

```ts
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;
    const SystemString = mscorlib.classes["System.String"];

    // simple trace, it only traces method calls
    Il2Cpp.Tracer.simpleTrace(SystemString);

    // full trace, it traces method calls and returns
    Il2Cpp.Tracer.fullTrace(SystemString);

    // full trace, it traces method calls and returns and it reports any value
    Il2Cpp.Tracer.fullWithValuesTrace(SystemString);

    // custom behaviour, it traces method returns and return values
    Il2Cpp.Tracer.trace((method: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
        const signature = `${method.name} (${method.parameterCount})`;
        return {
            onLeave(returnValue: Il2Cpp.Method.ReturnType) {
                console.log(`[custom log] ${signature} ----> ${returnValue}`);
            }
        };
    }, SystemString);
});
```

There are three already defined strategies you can follow in order to trace methods. I will use `onEnter` and `onLeave`
words, however `Il2Cpp.Tracer` does not use `Interceptor.attach`, but a combination of `Interceptor.replace` and
`NativeFunction` ([here's why](https://t.me/fridadotre/52178)).

- `Il2Cpp.Tracer.Simple` only reports `onEnter` calls.
  ```~~~~
  [il2cpp] 0x01a3cfbc System.String.FastAllocateString
  [il2cpp] 0x01a3daf4 System.String.IsNullOrEmpty
  [il2cpp] 0x01a30f2c System.String.Replace
  [il2cpp] 0x01a42054 System.String.ReplaceInternal
  [il2cpp] 0x01a43ae8 System.String.ReplaceUnchecked
  [il2cpp] 0x01a36ed8 System.String.get_Chars
  [il2cpp] 0x01a36ed8 System.String.get_Chars
  [il2cpp] 0x01a41f60 System.String.Replace
  [il2cpp] 0x01a41f64 System.String.ReplaceInternal
  [il2cpp] 0x01a4346c System.String.IndexOfUnchecked
  [il2cpp] 0x01a3cfbc System.String.FastAllocateString
  ```

- `Il2Cpp.Tracer.Full` reports both `onEnter` and `onLeave` nicely.
  ```
  [il2cpp] 0x01a3cfbc ┌─System.String.FastAllocateString
  [il2cpp] 0x01a3cfbc └─System.String.FastAllocateString
  
  [il2cpp] 0x01a3daf4 ┌─System.String.IsNullOrEmpty
  [il2cpp] 0x01a3daf4 └─System.String.IsNullOrEmpty
  
  [il2cpp] 0x01a30f2c ┌─System.String.Replace
  [il2cpp] 0x01a42054 │ ┌─System.String.ReplaceInternal
  [il2cpp] 0x01a43ae8 │ │ ┌─System.String.ReplaceUnchecked
  [il2cpp] 0x01a36ed8 │ │ │ ┌─System.String.get_Chars
  [il2cpp] 0x01a36ed8 │ │ │ └─System.String.get_Chars
  [il2cpp] 0x01a36ed8 │ │ │ ┌─System.String.get_Chars
  [il2cpp] 0x01a36ed8 │ │ │ └─System.String.get_Chars
  [il2cpp] 0x01a41f60 │ │ │ ┌─System.String.Replace
  [il2cpp] 0x01a41f64 │ │ │ │ ┌─System.String.ReplaceInternal
  [il2cpp] 0x01a4346c │ │ │ │ │ ┌─System.String.IndexOfUnchecked
  [il2cpp] 0x01a4346c │ │ │ │ │ └─System.String.IndexOfUnchecked
  [il2cpp] 0x01a41f60 │ │ │ │ └─System.String.Replace
  [il2cpp] 0x01a41f64 │ │ │ └─System.String.ReplaceInternal
  [il2cpp] 0x01a43ae8 │ │ └─System.String.ReplaceUnchecked
  [il2cpp] 0x01a42054 │ └─System.String.ReplaceInternal
  [il2cpp] 0x01a30f2c └─System.String.Replace
  
  [il2cpp] 0x01a3cfbc ┌─System.String.FastAllocateString
  [il2cpp] 0x01a3cfbc └─System.String.FastAllocateString
  ```

- `Il2Cpp.Tracer.FullWithValues` reports both `onEnter` and `onLeave` nicely, plus every printable value.
  ```
  [il2cpp] 0x01a3cfbc ┌─System.String.FastAllocateString(System.Int32 length = 1)
  [il2cpp] 0x01a3cfbc └─System.String.FastAllocateString System.String =
  
  [il2cpp] 0x01a3daf4 ┌─System.String.IsNullOrEmpty(System.String value = assets/bin/Data/)
  [il2cpp] 0x01a3daf4 └─System.String.IsNullOrEmpty System.Boolean = false
  
  [il2cpp] 0x01a30f2c ┌─System.String.Replace(System.String oldValue = \, System.String newValue = /)
  [il2cpp] 0x01a42054 │ ┌─System.String.ReplaceInternal(System.String oldValue = \, System.String newValue = /)
  [il2cpp] 0x01a43ae8 │ │ ┌─System.String.ReplaceUnchecked(System.String oldValue = \, System.String newValue = /)
  [il2cpp] 0x01a36ed8 │ │ │ ┌─System.String.get_Chars(System.Int32 index = 0)
  [il2cpp] 0x01a36ed8 │ │ │ └─System.String.get_Chars System.Char = 92
  [il2cpp] 0x01a36ed8 │ │ │ ┌─System.String.get_Chars(System.Int32 index = 0)
  [il2cpp] 0x01a36ed8 │ │ │ └─System.String.get_Chars System.Char = 47
  [il2cpp] 0x01a41f60 │ │ │ ┌─System.String.Replace(System.Char oldChar = 92, System.Char newChar = 47)
  [il2cpp] 0x01a41f64 │ │ │ │ ┌─System.String.ReplaceInternal(System.Char oldChar = 92, System.Char newChar = 47)
  [il2cpp] 0x01a4346c │ │ │ │ │ ┌─System.String.IndexOfUnchecked(System.Char value = 92, System.Int32 startIndex = 0, System.Int32 count = 16)
  [il2cpp] 0x01a4346c │ │ │ │ │ └─System.String.IndexOfUnchecked System.Int32 = 4294967295
  [il2cpp] 0x01a41f60 │ │ │ │ └─System.String.Replace System.String = assets/bin/Data/
  [il2cpp] 0x01a41f64 │ │ │ └─System.String.ReplaceInternal System.String = assets/bin/Data/
  [il2cpp] 0x01a43ae8 │ │ └─System.String.ReplaceUnchecked System.String = assets/bin/Data/
  [il2cpp] 0x01a42054 │ └─System.String.ReplaceInternal System.String = assets/bin/Data/
  [il2cpp] 0x01a30f2c └─System.String.Replace System.String = assets/bin/Data/
  
  [il2cpp] 0x01a3cfbc ┌─System.String.FastAllocateString(System.Int32 length = 0)
  [il2cpp] 0x01a3cfbc └─System.String.FastAllocateString System.String = 
  ```

> The output is nicely coloured so you won't get crazy when inspecting the console.

### Heap scan

```ts
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;
    const SystemType = mscorlib.classes["System.Type"];

    // it relies on classes gc descriptors
    Il2Cpp.GC.choose(SystemType).forEach((instance: Il2Cpp.Object) => {
        // instance.class.type.name == "System.Type"
    });

    const snapshot = Il2Cpp.MemorySnapshot.capture();

    // it relies on a memory snapshot
    snapshot.objects.filter(Il2Cpp.Filtering.IsExactly(SystemType)).forEach((instance: Il2Cpp.Object) => {
        // instance.class.type.name == "System.Type"
    });

    snapshot.free();
});
```

You can "scan" the heap or whatever the place where the objects get allocated in to find instances of the given class.
There are two ways of doing this: reading classes GC descriptors or taking a memory snapshot. However, I don't really
know how they internally work, I read enough uncommented C++ source code for my taste.

### Methods

```ts
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;
    const SystemString = mscorlib.classes["System.String"];

    const IsNullOrEmpty = mscorlib.classes["System.String"].methods.IsNullOrEmpty;
    const MemberwiseClone = mscorlib.classes["System.Object"].methods.MemberwiseClone;

    const string = Il2Cpp.String.from("Hello, il2cpp!");

    // static method invocation, it will return false
    const result0 = IsNullOrEmpty.invoke<boolean>(string);

    // instance method invocation, it will return true
    const result1 = string.object.methods.Contains.invoke<boolean>(Il2Cpp.String.from("il2cpp"));

    // 
    IsNullOrEmpty.implementation = function (value: Il2Cpp.String): boolean {
        value.content = "!"; // <--- onEnter
                             // <--- onEnter
        const result = this.methods.IsNullOrEmpty.invoke(value);
        // <--- onLeave
        console.log(result); // <--- onLeave
        return !!result;     // <--- onLeave
    };

    //
    MemberwiseClone.implementation = function (): Il2Cpp.Object {
        // `this` is a "System.Object", because MemberwiseClone is a System.Object method

        // `originalInstance` can be any type
        const originalInstance = new Il2Cpp.Object(this.handle);

        // not cloning!
        return this as Il2Cpp.Object;
    };
});
```

- #### Invocation
  You can invoke any method using `invoke` (this is just an abstraction over `NativeFunction`).


- #### Replacement & Interception
  You can replace and intercept any method implementation using `implementation` (this is just an abstraction over `Interceptor.replace` and `NativeCallback`). If the method is static, `this` will be a `Il2Cpp.Class`, or `Il2Cpp.Object` otherwise: the instance is artificially down-casted to the method declaring class. \
  Some other examples:
  ```ts
  // System.Int32 GetByteCount(System.Char[] chars, System.Int32 index, System.Int32 count, System.Boolean flush);
  GetByteCount.implementation =
          function (chars: Il2Cpp.Array<number>, index: number, count: number, flush: boolean): number {}
  
  // System.Boolean InternalFallback(System.Char ch, System.Char*& chars);
  InternalFallback.implementation = 
          function (ch: number, chars: Il2Cpp.Reference<Il2Cpp.Pointer<number>>): boolean {}
  ```

### Generics handling

Dealing with generics is problematic when the `global-metadata.dat` file is ignored. You can
gather the inflated version (if any) via `Il2Cpp.Class.inflate` and `Il2Cpp.method.inflate`.
Reference types (aka objects) all shares the same code: it is easy to retrieve virtual address in this case. Value types (aka primitives and structs) does not share any code.
`inflate` will always return an inflated class or method (you must match the number of type arguments with the number of types you pass to `inflate`), but the returned value it's not
necessarely a class or method that has been implemented.
```ts
Il2Cpp.perform(() => {
    const classes = Il2Cpp.Image.corlib.classes;

    const SystemObject = classes["System.Object"];
    const SystemInt32 = classes["System.Object"];


    const GenericList = classes["System.Collections.Generic.List<T>"];

    // This class is shared among all reference types
    const SystemObjectList = GenericList.inflate(SystemObject);

    // This class is specific to System.Int32, because it's a value type
    const SystemInt32List = GenericList.inflate(SystemInt32);


    // static T UnsafeCast(System.Object o);
    const UnsafeCast = classes["System.Runtime.CompilerServices.JitHelpers"].methods.UnsafeCast;
    // UnsafeCast is a generic method, its virtual address is null

    // This is the UnsafeCast for every reference type
    const SystemObjectUnsafeCast = UnsafeCast.inflate(SystemObject);

    // This doesn't make sense, but this is the UnsafeCast specific to System.Int32, because it's a value type
    const SystemInt32UnsafeCast = UnsafeCast.inflate(SystemInt32);
});
```

---

## Miscellaneous

### How to handle overloading

There's not a nice way to handle overloading yet (there's no such `.overload(...)` thing yet). However, method gets
renamed. Consider the following `System.String` methods:

```cs
System.Boolean Equals(System.Object obj); // SystemString.methods.Equals
System.Boolean Equals(System.String value); // SystemString.methods.Equals_
System.Boolean Equals(System.String value, System.StringComparison comparisonType); // SystemString.methods.Equals__
```

Basically, an underscore is appended to the method name (key) until the key can be used.

### Ghidra script

The following script parses the file outputted by `Il2Cpp.Dumper` and looks for methods using regular expression.

```py
import re
from ghidra.program.model.address import AddressFactory
from ghidra.program.model.symbol.SourceType import USER_DEFINED

address_factory = getAddressFactory()

with open("/path/to/dump.cs", "r") as file:
    content = file.read()

matches = re.findall("([^\s]+)(?:\(.+)(0x[0123456789abcdef]{8})", content)

for match in matches:
    function = getFunctionAt(address_factory.getAddress(match[1]))
    if function:
        function.setName(match[0], USER_DEFINED)
```