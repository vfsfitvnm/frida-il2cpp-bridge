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
    * [Replacement](#replacement)
    * [Interception](#interception)

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
(its name `_.js` here). \
Learn more about `packages.json` [here](https://docs.npmjs.com/cli/v7/configuring-npm/package-json).
```json
{
  "name": "project",
  "version": "1.0.0",
  "private": true,
  "main": "index.ts",
  "scripts": {
    "build": "frida-compile -o _.js -S -w index.ts",
    "spawn_and_attach": "frida -U -f TARGET -l _.js --runtime=v8 --no-pause",
    "just_attach": "frida -U TARGET -l _.js"
  },
  "devDependencies": {
    "@types/frida-gum": "^17.0.0",
    "@types/node": "^16.3.3",
    "frida-compile": "^10.2.4",
    "frida-il2cpp-bridge": "^0.3.1"
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
You import the global `Il2Cpp` object and initialize in the following way. \
This procedure is asynchronous because it may need to wait for IL2CPP module load and initialization (`il2cpp_init`). 

```ts
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();
}

main().catch(error => console.log(error.stack));
```

### Dump
You can perform an application dump quite easily. \
Make sure the target has write-permissions to the destination.
```ts
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();

    Il2Cpp.dump("/full/path/to/file.cs");
}

main().catch(error => console.log(error.stack));
```
If you don't provide a path, the code will try to build it. For instance, this will be
`/storage/emulated/0/Android/data/com.example.application/files/com.example.application_1.2.3.cs` on Android.

The dump will produce the following output:
```cs
// mscorlib.dll
struct System.Int32 : System.ValueType, System.IFormattable, System.IConvertible, System.IComparable, System.IComparable<System.Int32>, System.IEquatable<System.Int32>
{
    System.Int32 MaxValue = 2147483647; // 0x0
    System.Int32 MinValue = -2147483648; // 0x0
    System.Int32 m_value; // 0x10

    System.Boolean System.IConvertible.ToBoolean(System.IFormatProvider provider); // 0x00bed724;
    System.Byte System.IConvertible.ToByte(System.IFormatProvider provider); // 0x00bed72c;
    System.Char System.IConvertible.ToChar(System.IFormatProvider provider); // 0x00bed734;
    System.DateTime System.IConvertible.ToDateTime(System.IFormatProvider provider); // 0x00bed73c;
    System.Decimal System.IConvertible.ToDecimal(System.IFormatProvider provider); // 0x00bed744;
    System.Double System.IConvertible.ToDouble(System.IFormatProvider provider); // 0x00bed74c;
    // ...
}

// ...
```

### Trace
You can also easily trace invocations of the given a classes methods and/or methods.
```ts
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();

    const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
    const CSharp = Il2Cpp.Domain.reference.assemblies["Assembly-CSharp"].image;

    const SystemString = mscorlib.classes["System.String"];
    const SystemObject = mscorlib.classes["System.Object"];
    const Account = CSharp.classes.Account;
    
    const tracer0 = Il2Cpp.Tracer.Simple(SystemString, Account.methods.isLoggedIn);
    
    const tracer1 = Il2Cpp.Tracer.Full(SystemString, Account.methods.isLoggedIn);
    
    const tracer2 = Il2Cpp.Tracer.FullWithValues(SystemString, Account.methods.isLoggedIn);
    
    const tracer3 = Il2Cpp.Tracer.Custom(function (this: Il2Cpp.Tracer, method: Il2Cpp.Method): InvocationListenerCallbacks {
      return method.createFridaInterceptCallbacks({
        onLeave(returnValue: Il2Cpp.WithValue): void {
          console.log(`[custom log] ${method.name} => ${returnValue.value} @ ${returnValue.valueHandle}`);
        }
      });
    }, SystemString, Account.methods.isLoggedIn);

    // adds to tracer2 another class to trace after 1 second
    setTimeout(() => {
        tracer2.add(SystemObject);
    }, 1000);
    
    // stops tracer0, tracer1, and tracer2 after 5 seconds
    setTimeout(() => {
        tracer0.clear();
        tracer1.clear();
        tracer2.clear();
    }, 5000);
    
}

main().catch(error => console.log(error.stack));
```
There are three default types of tracing.
All the examples will trace every `System.String` method invocation and the method `Account.isLoggedIn`.

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
  [il2cpp] 0x01a3cfbc ┌─System.String.FastAllocateString(length: System.Int32 = 1)
  [il2cpp] 0x01a3cfbc └─System.String.FastAllocateString System.String =
  
  [il2cpp] 0x01a3daf4 ┌─System.String.IsNullOrEmpty(value: System.String = assets/bin/Data/)
  [il2cpp] 0x01a3daf4 └─System.String.IsNullOrEmpty System.Boolean = false
  
  [il2cpp] 0x01a30f2c ┌─System.String.Replace(oldValue: System.String = \, newValue: System.String = /)
  [il2cpp] 0x01a42054 │ ┌─System.String.ReplaceInternal(oldValue: System.String = \, newValue: System.String = /)
  [il2cpp] 0x01a43ae8 │ │ ┌─System.String.ReplaceUnchecked(oldValue: System.String = \, newValue: System.String = /)
  [il2cpp] 0x01a36ed8 │ │ │ ┌─System.String.get_Chars(index: System.Int32 = 0)
  [il2cpp] 0x01a36ed8 │ │ │ └─System.String.get_Chars System.Char = 92
  [il2cpp] 0x01a36ed8 │ │ │ ┌─System.String.get_Chars(index: System.Int32 = 0)
  [il2cpp] 0x01a36ed8 │ │ │ └─System.String.get_Chars System.Char = 47
  [il2cpp] 0x01a41f60 │ │ │ ┌─System.String.Replace(oldChar: System.Char = 92, newChar: System.Char = 47)
  [il2cpp] 0x01a41f64 │ │ │ │ ┌─System.String.ReplaceInternal(oldChar: System.Char = 92, newChar: System.Char = 47)
  [il2cpp] 0x01a4346c │ │ │ │ │ ┌─System.String.IndexOfUnchecked(value: System.Char = 92, startIndex: System.Int32 = 0, count: System.Int32 = 16)
  [il2cpp] 0x01a4346c │ │ │ │ │ └─System.String.IndexOfUnchecked System.Int32 = 4294967295
  [il2cpp] 0x01a41f60 │ │ │ │ └─System.String.Replace System.String = assets/bin/Data/
  [il2cpp] 0x01a41f64 │ │ │ └─System.String.ReplaceInternal System.String = assets/bin/Data/
  [il2cpp] 0x01a43ae8 │ │ └─System.String.ReplaceUnchecked System.String = assets/bin/Data/
  [il2cpp] 0x01a42054 │ └─System.String.ReplaceInternal System.String = assets/bin/Data/
  [il2cpp] 0x01a30f2c └─System.String.Replace System.String = assets/bin/Data/
  
  [il2cpp] 0x01a3cfbc ┌─System.String.FastAllocateString(length: System.Int32 = 0)
  [il2cpp] 0x01a3cfbc └─System.String.FastAllocateString System.String =
  ```
  
The output is nicely coloured so you won't get crazy when inspecting the log.

### Heap scan
You can "scan" the heap or whatever the place where the objects gets allocated in to find instances of the given
class. \
There are two ways of doing this:

- Reading classes GC descriptors
  ```ts
  import "frida-il2cpp-bridge";
  
  async function main() {
      await Il2Cpp.initialize();
    
      const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
      const SystemType = mscorlib.classes["System.Type"];
    
      Il2Cpp.GC.choose(SystemType).forEach(instance => {
          // instance.class.type.name == "System.Type"
      });
  }
  
  main().catch(error => console.log(error.stack));
  ```

- Taking a memory snapshot
  ```ts
  import "frida-il2cpp-bridge";
  
  async function main() {
      await Il2Cpp.initialize();
    
      const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
      const SystemType = mscorlib.classes["System.Type"];
    
      new Il2Cpp.MemorySnapshot().objects.filter(Il2Cpp.Filtering.IsExactly(SystemType)).forEach(instance => {
          // instance.class.type.name == "System.Type"
      });
  }
  
  main().catch(error => console.log(error.stack));
  ```
  The memory snapshot will be automatically freed, but you can do it explicitly.

### Methods

- #### Invocation
  You can invoke any method (this is just an abstraction over `NativeFunction`).
  ```ts
  import "frida-il2cpp-bridge";
  
  async function main() {
      await Il2Cpp.initialize();
    
      const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
      const SystemString = mscorlib.classes["System.String"];
      
      const string = Il2Cpp.String.from("Hello, il2cpp!");
      
      // static method invocation
      const result0 = SystemString.methods.IsNullOrEmpty.invoke<boolean>(string); // false
      
      // instance method invocation
      const result1 = string.object.methods.Contains.invoke<boolean>(Il2Cpp.String.from("il2cpp")); // true
  }
  
  main().catch(error => console.log(error.stack));
  ```

- #### Replacement
  You can replace any method implementation (this is just an abstraction over `Interceptor.replace` and `NativeCallback`).
  ```ts
  import "frida-il2cpp-bridge";
  
  async function main() {
      await Il2Cpp.initialize();
    
      const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
      const IsNullOrEmpty = mscorlib.classes["System.String"].methods.IsNullOrEmpty;
      
      IsNullOrEmpty.implementation = (instance: Il2Cpp.Object | null, parameters: Readonly<Record<string, Il2Cpp.WithValue>>) => {
          parameters.value.value = Il2Cpp.String.from("Hello!");
  
          // restores the original implementation after 1 second
          setTimeout(() => {
              IsNullOrEmpty.implementation = null;
          }, 1000);
          
          return 0;
      };
  }
  
  main().catch(error => console.log(error.stack));
  ```

- #### Interception
  You can intercept any method invocation (this is just an abstraction over `Interceptor.attach`).
  ```ts
  import "frida-il2cpp-bridge";
  
  async function main() {
      await Il2Cpp.initialize();
    
      const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
      const IsNullOrEmpty = mscorlib.classes["System.String"].methods.IsNullOrEmpty;
  
      IsNullOrEmpty.intercept({
          onEnter(instance: Il2Cpp.Object | null, parameters: Readonly<Record<string, Il2Cpp.WithValue>>) {
              parameters.value.value = Il2Cpp.String.from("Replaced!");
          },
          onLeave(returnValue: Il2Cpp.WithValue) {
              returnValue.value = true;
          }
      });
  }
  
  main().catch(error => console.log(error.stack));
  ```
  