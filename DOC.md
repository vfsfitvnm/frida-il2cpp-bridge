# frida-il2cpp-bridge documentation

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
    * [Replacement & Interception](#replacement-&-interception)
* [Miscellaneous](#miscellaneous)
  * [How to handle overloading](#how-to-handle-overloading)

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
This is where you write the code. `frida-il2cpp-bridge` needs to be initialized asynchronously, hence the `async` block
(you can use `Promise` as well, of course).
```ts
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();

    // <code>
}

main().catch(error => console.log(error.stack));
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
    "attach-with-spawn": "run() { frida -U -f \"$1\" -l _.js --no-pause --runtime=v8; }; run",
    "app0-with-spawn": "npm run attach-with-spawn com.example.application0",
    "app1": "npm run \"Application1 Name\"",
    "app1-with-spawn": "npm run attach-with-spawn com.example.application1"
  },
  "devDependencies": {
    "@types/frida-gum": "^17.1.0",
    "frida-compile": "^10.2.4",
    "frida-il2cpp-bridge": "^0.4.7"
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

async function main() {
    await Il2Cpp.initialize();
}

main().catch(error => console.log(error.stack));
```
You import the global `Il2Cpp` object and initialize in the following way. \
This procedure is asynchronous because it may need to wait for IL2CPP module load and initialization (`il2cpp_init`).

### Dump
```ts
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();
    
    // it will use default directory path and file name: /<default_path>/<default_name>.cs
    Il2Cpp.Dumper.classicDump();
    
    // the file name is overridden: /<default_path>/custom_file_name.cs
    Il2Cpp.Dumper.classicDump("custom_file_name");

    // the file name and directory path are overridden: /i/can/write/to/this/path/custom_file_name.cs
    Il2Cpp.Dumper.classicDump("custom_file_name", "/i/can/write/to/this/path");
    
    // alternatively
    Il2Cpp.Dumper.snapshotDump();
}

main().catch(error => console.log(error.stack));
```
There are two already defined strategies you can follow in order to dump the application. \
The **first one**, the _classic dump_, iterates
all the assemblies, and then dump all the classes inside them. This strategy is pretty straightforward, however it
misses quite few classes (array and inflated classes - `System.String[]` and
`System.Collections.Generic.List<System.String>` for instance). These _missing_ classes do not contain any "hidden"
code, however they may be useful during static analysis. \
The **second one**, the _snapshot dump_, comes to the rescue. It performs a memory snapshot
(IL2CPP generously exposes the APIs), which also includes  the classes the classic dump could not easily guess,
thankfully. However, the snapshot only reports already initialized classes: it's important to run this dump as
late as possible. The second dump seems to include the same classes the first one would find.

Dumping may require two parameters: a directory path (e.g. a place where the application can write to) and a file name.
If not provided, the code will just guess them;
however it might fail on some applications and/or Unity versions.

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

async function main() {
    await Il2Cpp.initialize();

    const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
    const CSharp = Il2Cpp.Domain.reference.assemblies["Assembly-CSharp"].image;

    const SystemString = mscorlib.classes["System.String"];
    const SystemObject = mscorlib.classes["System.Object"];
    const Account = CSharp.classes.Account;
    
    // simple trace, it only traces method calls
    Il2Cpp.Tracer.simpleTrace(SystemString, Account.methods.isLoggedIn);
    
    // full trace, it traces method calls and returns
    Il2Cpp.Tracer.fullTrace(SystemString, Account.methods.isLoggedIn);

    // full trace, it traces method calls and returns and it reports any value
    Il2Cpp.Tracer.fullWithValuesTrace(SystemString, Account.methods.isLoggedIn);
    
    // custom behaviour, it traces method returns and return values
    Il2Cpp.Tracer.trace((method: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
        const signature = `${method.name} (${method.parameterCount})`;
        return {
            onLeave(returnValue: Il2Cpp.Method.ReturnType) {
                console.log(`[custom log] ${signature} ----> ${returnValue}`);
            }
        };
    }, SystemString, Account.methods.isLoggedIn);    
}

main().catch(error => console.log(error.stack));
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

async function main() {
    await Il2Cpp.initialize();
  
    const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
    const SystemType = mscorlib.classes["System.Type"];
    
    // it relies on classes gc descriptors
    Il2Cpp.GC.choose(SystemType).forEach((instance: Il2Cpp.Object) => {
        // instance.class.type.name == "System.Type"
    });
    
    // it relies on a memory snapshot
    new Il2Cpp.MemorySnapshot().objects
        .filter(Il2Cpp.Filtering.IsExactly(SystemType))
        .forEach((instance: Il2Cpp.Object) => {
            // instance.class.type.name == "System.Type"
        });

    // the memory snapshot will be automatically freed, but you can do it explicitly
}

main().catch(error => console.log(error.stack));
```
You can "scan" the heap or whatever the place where the objects get allocated in to find instances of the given
class. There are two ways of doing this: reading classes GC descriptors or taking a memory snapshot. However, I don't
really know how they internally work, I read enough uncommented C++ source code for my taste.

### Methods
```ts
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();
  
    const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
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
        return result;       // <--- onLeave
    };
    
    //
    MemberwiseClone.implementation = function (): Il2Cpp.Object {
        // `this` is a "System.Object", because MemberwiseClone is a System.Object method
    
        // `originalInstance` can be any type
        const originalInstance = new Il2Cpp.Object(this.handle);
    
        // not cloning!
        return this as Il2Cpp.Object;
    };
}

main().catch(error => console.log(error.stack));
```

- #### Invocation
  You can invoke any method using `invoke` (this is just an abstraction over `NativeFunction`).


- #### Replacement & Interception
  You can replace and intercept any method implementation using `implementation` (this is just an abstraction over 
  `Interceptor.replace` and `NativeCallback`). It follows `frida-java-bridge` syntax.
  If the method is static, `this` will be a `Il2Cpp.Class`, or `Il2Cpp.Object` otherwise: the instance is artificially
  down-casted to the method declaring class. \
  Some other examples:
  ```ts
  // System.Int32 GetByteCount(System.Char[] chars, System.Int32 index, System.Int32 count, System.Boolean flush);
  GetByteCount.implementation =
          function (chars: Il2Cpp.Array<number>, index: number, count: number, flush: boolean): number {}
  
  // System.Boolean InternalFallback(System.Char ch, System.Char*& chars);
  InternalFallback.implementation = 
          function (ch: number, chars: Il2Cpp.Reference<Il2Cpp.Pointer<number>>): boolean {}
  ```

---

## Miscellaneous

### How to handle overloading
There's not a nice way to handle overloading yet (there's no such `.overload(...)` method). However, method gets
renamed. Consider the following `System.String` methods:
```cs
System.Boolean Equals(System.Object obj); // SystemString.methods.Equals
System.Boolean Equals(System.String value); // SystemString.methods.Equals_
System.Boolean Equals(System.String value, System.StringComparison comparisonType); // SystemString.methods.Equals__
```
Basically, an underscore is appended to the method name (key) until the key can be used.

