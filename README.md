# frida-il2cpp-bridge

[![Frida](https://img.shields.io/badge/-frida-ef6456?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyAgIHZlcnNpb249IjEuMSIgICBpZD0iTGF5ZXJfMSIgICB4PSIwcHgiICAgeT0iMHB4IiAgIHZpZXdCb3g9IjAgMCA5LjcyOTk3OTkgMTAuOTM1NzEyIiAgIGVuYWJsZS1iYWNrZ3JvdW5kPSJuZXcgMCAwIDIwNC40IDM5IiAgIHhtbDpzcGFjZT0icHJlc2VydmUiICAgc29kaXBvZGk6ZG9jbmFtZT0ibG9nby5zdmciICAgd2lkdGg9IjkuNzI5OTc5NSIgICBoZWlnaHQ9IjEwLjkzNTcxMiIgICBpbmtzY2FwZTp2ZXJzaW9uPSIxLjEgKGNlNjY2M2IzYjcsIDIwMjEtMDUtMjUpIiAgIHhtbG5zOmlua3NjYXBlPSJodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy9uYW1lc3BhY2VzL2lua3NjYXBlIiAgIHhtbG5zOnNvZGlwb2RpPSJodHRwOi8vc29kaXBvZGkuc291cmNlZm9yZ2UubmV0L0RURC9zb2RpcG9kaS0wLmR0ZCIgICB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnMgICBpZD0iZGVmczkiIC8+PHNvZGlwb2RpOm5hbWVkdmlldyAgIGlkPSJuYW1lZHZpZXc3IiAgIHBhZ2Vjb2xvcj0iI2ZmZmZmZiIgICBib3JkZXJjb2xvcj0iIzY2NjY2NiIgICBib3JkZXJvcGFjaXR5PSIxLjAiICAgaW5rc2NhcGU6cGFnZXNoYWRvdz0iMiIgICBpbmtzY2FwZTpwYWdlb3BhY2l0eT0iMC4wIiAgIGlua3NjYXBlOnBhZ2VjaGVja2VyYm9hcmQ9IjAiICAgc2hvd2dyaWQ9ImZhbHNlIiAgIGZpdC1tYXJnaW4tdG9wPSIwIiAgIGZpdC1tYXJnaW4tbGVmdD0iMCIgICBmaXQtbWFyZ2luLXJpZ2h0PSIwIiAgIGZpdC1tYXJnaW4tYm90dG9tPSIwIiAgIGlua3NjYXBlOnpvb209IjYuOTE3ODA4NCIgICBpbmtzY2FwZTpjeD0iLTAuMTQ0NTU0NDUiICAgaW5rc2NhcGU6Y3k9Ii04LjYwMDk4OTkiICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxOTIwIiAgIGlua3NjYXBlOndpbmRvdy1oZWlnaHQ9IjEwMDgiICAgaW5rc2NhcGU6d2luZG93LXg9IjAiICAgaW5rc2NhcGU6d2luZG93LXk9IjAiICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSIgICBpbmtzY2FwZTpjdXJyZW50LWxheWVyPSJMYXllcl8xIiAvPjxnICAgaWQ9Imc0IiAgIHN0eWxlPSJkaXNwbGF5OmlubGluZTtmaWxsOiNmZmZmZmYiICAgdHJhbnNmb3JtPSJtYXRyaXgoMC4yODA0MDI4NiwwLDAsMC4yODA0MDI4NiwtMTEuNTgwNjM4LDApIj48cGF0aCAgIGZpbGw9IiNmZmZmZmYiICAgZD0iTSA1MS40LDM5IEggNDEuMyBMIDQ5LjcsMjYuMSBDIDQ0LjksMjMuOCA0Mi4zLDE5LjYgNDIuMywxMy41IDQyLjMsNC44IDQ4LjIsMCA1OC41LDAgSCA3NiBWIDM5IEggNjcgViAyOCBIIDU4LjUgNTcuNyBaIE0gNjcsMjAgViA3IGggLTguNSBjIC00LjksMCAtNy43LDIgLTcuNyw2LjQgMCw0LjUgMi44LDYuNiA3LjcsNi42IHoiICAgaWQ9InBhdGgyIiAgIHN0eWxlPSJmaWxsOiNmZmZmZmYiIC8+PC9nPjwvc3ZnPg==)](https://frida.re)
[![NPM](https://img.shields.io/npm/v/frida-il2cpp-bridge?label=&logo=npm&style=for-the-badge)](https://npmjs.org/package/frida-il2cpp-bridge)

Frida module to dump, manipulate and hijack any IL2CPP application at runtime with a high level
 of abstraction, without needing the `global-metadata.dat` file.

```ts
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();
    
    const TestAssembly = Il2Cpp.Domain.reference.assemblies["Test.Assembly"].image;
    
    TestAssembly.classes.TestClass.methods.testMethod.intercept({
        onLeave(returnValue) { 
            const testObject = returnValue.value as Il2Cpp.Object;
            testObject.fields.testField.value = 100;
            testObject.methods.newTestMethod.invoke(false, Il2Cpp.String.from("testString"));
        }
    });
    
    TestAssembly.classes.NewTestClass.trace();
}

main().catch(error => console.log(error.stack));
```

### Version support
![](https://img.shields.io/badge/-(from)%205.3.0-222c37?logo=unity&style=for-the-badge&logoColor=white)
![](https://img.shields.io/badge/-(to)%202021.1.0-222c37?logo=unity&style=for-the-badge&logoColor=white)

Thanks to [Il2CppInspector](https://github.com/djkaty/Il2CppInspector)
for providing the headers.

### Platform support

![](https://img.shields.io/badge/-not_tested-yellow?logo=linux&style=for-the-badge&logoColor=white)
![](https://img.shields.io/badge/-tested-green?logo=android&style=for-the-badge&logoColor=white)
![](https://img.shields.io/badge/-not_tested-yellow?logo=windows&style=for-the-badge&logoColor=white)
![](https://img.shields.io/badge/-missing_device-red?logo=ios&style=for-the-badge)

### Project setup
Please take a look at the `example` folder.
You can download it [here](https://minhaskamal.github.io/DownGit/#/home?url=https://github.com/vfsfitvnm/frida-il2cpp-bridge/tree/master/example).

### Add to an existing project
```shell script
npm install --save-dev frida-il2cpp-bridge
```
You _may_ need to include `"moduleResolution": "node"` in your `tsconfig.json`.

### Known limitations
- Lack of support for reference types (e.g. `System.Boolean&`)
- Absent generic classes or methods utilities
- Probably a lot more

### Snippets
* [`Initialization`](#initialization)
* [`Dump`](#dump)
* [`Find every instance of a certain class`](#find-instances)
* [`Class tracing`](#class-tracing)
* [`Method tracing`](#method-tracing)
* [`Method replacement`](#method-replacement)
* [`Method interception`](#method-interception)

##### Initialization
```ts
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();
}

main().catch(error => console.log(error.stack));
```

##### Dump
Make sure the target has write-permissions to the destination.
```ts
Il2Cpp.dump("/full/path/to/file.cs");
```
If you don't provide a path, it will be automatically detected. For instance, this will be 
`/storage/emulated/0/Android/data/com.example.application/files/com.example.application_1.2.3.cs` on Android.
```ts
Il2Cpp.dump();
```

This will produce something like:
```cs
// mscorlib.dll
class <Module>
{
}

// mscorlib.dll
class Locale : System.Object
{
    static System.String GetText(System.String msg); // 0x01fbb020
    static System.String GetText(System.String fmt, System.Object[] args); // 0x01803a38
}
```

##### Find instances
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const SystemType = msmscorlib.classes["System.Type"];

Il2Cpp.GC.choose(SystemType).forEach(instance => {
    // Do whatever you want
    assert(instance.class.type.name == "System.Type");
});
```
Alternatively
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const SystemString = msmscorlib.classes["System.String"];

new Il2Cpp.MemorySnapshot().objects.filter(Il2Cpp.Filtering.IsExactly(SystemString)).forEach(instance => {
   // Do whatever you want
   assert(instance.class.type.name == "System.Type[]");
});
```

##### Class tracing
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const SystemString = msmscorlib.classes["System.String"];

SystemString.trace();
```
It will log something like:
```
[il2cpp] 0x015ed550 get_Chars
[il2cpp] 0x005602f0 FastAllocateString
[il2cpp] 0x00ab497c wstrcpy
[il2cpp] 0x01a62bc0 IsNullOrEmpty
[il2cpp] 0x015ed550 get_Chars
[il2cpp] 0x015ed550 get_Chars
````

##### Method tracing
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const IsNullOrEmpty = msmscorlib.classes["System.String"].methods.IsNullOrEmpty;

IsNullOrEmpty.trace();
```
It will log something like:
```coffeescriptliterate
[il2cpp] 0x01a62bc0 IsNullOrEmpty
[il2cpp] 0x01a62bc0 IsNullOrEmpty
[il2cpp] 0x01a62bc0 IsNullOrEmpty
````

##### Method replacement
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const IsNullOrEmpty = msmscorlib.classes["System.String"].methods.IsNullOrEmpty;

IsNullOrEmpty.implementation = (instance, parameters) => {
    parameters.value.value = Il2Cpp.String.from("Hello!");
    return 0;
};
```

Later on, to revert the replacement:
```ts
IsNullOrEmpty.implementation = null;
```


##### Method interception
You can replace any of the parameters and the return value by reassigning them.
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const SystemString = msmscorlib.classes["System.String"];

SystemString.methods.IsNullOrEmpty.intercept({
    onEnter(instance, parameters) {
        parameters.value = Il2Cpp.String.from("Replaced!");
        assert((parameters.value.value as Il2Cpp.String).content == "Replaced!");
    },
    onLeave(returnValue) {
        returnValue.value = true;
    }
});
```

### API
* [`Il2Cpp.Array`](#il2cpparray)
* [`Il2Cpp.Assembly`](#il2cppassembly)
* [`Il2Cpp.Class`](#il2cppclass)
* [`Il2Cpp.Domain`](#il2cppdomain)
* [`Il2Cpp.Field`](#il2cppfield)
* [`Il2Cpp.Image`](#il2cppimage)
* [`Il2Cpp.Method`](#il2cppmethod)
* [`Il2Cpp.Object`](#il2cppobject)
* [`Il2Cpp.Parameter`](#il2cppparameter)
* [`Il2Cpp.String`](#il2cppstring)
* [`Il2Cpp.Type`](#il2cpptype)
* [`Il2Cpp.ValueType`](#il2cppvaluetype)


##### `Il2Cpp.Array`
It's not possible to add or remove an array element at the moment.
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const SystemString = msmscorlib.classes["System.String"];

const arr = Il2Cpp.Array.from<Il2Cpp.String>(SystemString, [
    Il2Cpp.String.from("One"), Il2Cpp.String.from("Two"), Il2Cpp.String.from("Three")
]);

assert(arr.elementSize == StringClass.arrayElementSize);

assert(arr.length == 3);

assert(arr.object.class.type.name == "System.String[]");

assert(arr.elementType.name == "System.String");

assert(Array.from(arr).join(",") == "One,Two,Three");

assert(arr.get(0).content == "One");
arr.set(0, Il2Cpp.String.from("Replaced"));
assert(arr.get(0).content == "Replaced");
```

##### `Il2Cpp.Assembly`
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

assert(mscorlib.name == "mscorlib");
```

##### `Il2Cpp.Class`
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

const BooleanClass = mscorlib.classes["System.Boolean"];
const Int32Class = mscorlib.classes["System.Int32"];
const Int64Class = mscorlib.classes["System.Int64"];
const ObjectClass = mscorlib.classes["System.Object"];
const DayOfWeekClass = mscorlib.classes["System.DayOfWeek"];
const MathClass = mscorlib.classes["System.Math"];
const IFormattableClass = mscorlib.classes["System.IFormattable"];
const ExecutionContextClass = mscorlib.classes["System.Threading.ExecutionContext"];
const ExecutionContextFlagsClass = mscorlib.classes["System.Threading.ExecutionContext.Flags"];

assert(BooleanClass.arrayClass.name == "Boolean[]");

assert(Int32Class.arrayElementSize == 4);
assert(Int64Class.arrayElementSize == 8);
assert(ObjectClass.arrayElementSize == Process.pointerSize);

assert(BooleanClass.arrayClass.elementClass?.name == "Boolean");

assert(ExecutionContextFlagsClass.declaringClass!.handle.equals(ExecutionContextClass.handle));

assert(Int32Class.hasStaticConstructor == ".cctor" in Int32Class.methods);

assert(Int32Class.image.name == "mscorlib.dll");

assert(DayOfWeekClass.isEnum);
assert(!ObjectClass.isEnum);

assert(IFormattableClass.isInterface);
assert(!ObjectClass.isInterface);

if (!MathClass.isStaticConstructorFinished) {
 MathClass.initialize();
 assert(MathClass.isStaticConstructorFinished);
}

assert(Int32Class.isValueType);
assert(!ObjectClass.isValueType);

assert(BooleanClass.name == "Boolean");

assert(BooleanClass.namespace == "System");

assert(BooleanClass.parent!.type.name == "System.ValueType");
assert(ObjectClass.parent == null);

assert(BooleanClass.type.name == "System.Boolean");
```

#### `Il2Cpp.Domain`
```ts
assert(Il2Cpp.Domain.reference.name == "IL2CPP Root Domain");
```

#### `Il2Cpp.Field`
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const coreModule = Il2Cpp.Domain.reference.assemblies["UnityEngine.CoreModule"].image;

const BooleanClass = mscorlib.classes["System.Boolean"];
const MathClass = mscorlib.classes["System.Math"];
const ThreadClass = mscorlib.classes["System.Threading.Thread"];
const Vector2Class = coreModule.classes["UnityEngine.Vector2"];

assert(MathClass.fields.PI.class.handle.equals(MathClass.handle));

assert(!Vector2Class.fields.x.isStatic);
assert(Vector2Class.fields.oneVector.isStatic);

assert(MathClass.fields.PI.isLiteral);

assert(ThreadClass.fields.current_thread.isThreadStatic);
assert(!ThreadClass.fields.m_Delegate.isThreadStatic);

assert(BooleanClass.fields.TrueLiteral.name == "TrueLiteral");

assert(MathClass.fields.PI.type.name == "System.Double");

const vec = Vector2Class.fields.oneVector.value as Il2Cpp.ValueType;
assert(vec.fields.x.value == 1);
assert(vec.fields.y.value == 1);

vec.fields.x.value = 42;
assert(vec.fields.x.value == 42);
```

#### `Il2Cpp.Image`
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

assert(mscorlib.name == "mscorlib.dll");
```

#### `Il2Cpp.Method`
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

const BooleanClass = mscorlib.classes["System.Boolean"];
const ArrayClass = mscorlib.classes["System.Array"];
const MathClass = mscorlib.classes["System.Math"];

assert(MathClass.methods.Sqrt.class.handle.equals(MathClass.handle));

assert(ArrayClass.methods.Empty.isGeneric);

assert(!BooleanClass.methods.ToString.isStatic);
assert(!BooleanClass.methods.Parse.isStatic);

assert(MathClass.methods.Sqrt.name == "Sqrt");

assert(MathClass.methods[".cctor"].parameterCount == 0);
assert(MathClass.methods.Abs.parameterCount == 1);
assert(MathClass.methods.Max.parameterCount == 2);

assert(BooleanClass.methods.Parse.invoke<boolean>(Il2Cpp.String.from("true")));

MathClass.methods.Max.implementation = (_instance, parameters) => {
 const val1 = parameters.val1.value as number;
 const val2 = parameters.val2.value as number;
 return val1 > val2 ? val2 : val1;
};
assert(MathClass.methods.Max.invoke<number>(1, 2) == 1);

MathClass.methods.Max.implementation = null;
assert(MathClass.methods.Max.invoke<number>(1, 2) == 2);

MathClass.methods.Max.intercept({
 onEnter(_instance, parameters) {
  parameters.val1.value = 10;
 }
});
assert(MathClass.methods.Max.invoke<number>(1, 2) == 10);
```

#### `Il2Cpp.Object`
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
const coreModule = Il2Cpp.Domain.reference.assemblies["UnityEngine.CoreModule"].image;

const OrdinalComparerClass = mscorlib.classes["System.OrdinalComparer"];
const Vector2Class = coreModule.classes["UnityEngine.Vector2"];

const ordinalComparer = Il2Cpp.Object.from(OrdinalComparerClass);
assert(ordinalComparer.class.name == "OrdinalComparer");
assert(ordinalComparer.base.class.name == "StringComparer");

const vec = Il2Cpp.Object.from(Vector2Class);
vec.methods[".ctor"].invoke(36, 4);

const vecUnboxed = vec.unbox();
assert(vec.fields.x.value == vecUnboxed.fields.x.value);
assert(vec.fields.y.value == vecUnboxed.fields.y.value);

const vecBoxed = vecUnboxed.box();
assert(vecBoxed.fields.x.value == vecUnboxed.fields.x.value);
assert(vecBoxed.fields.y.value == vecUnboxed.fields.y.value);

assert(!vecBoxed.handle.equals(vec.handle));
```

#### `Il2Cpp.Parameter`
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

const dParameter = mscorlib.classes["System.Math"].methods.Sqrt.parameters.d;

assert(dParameter.name == "d");

assert(dParameter.position == 0);

assert(dParameter.type.name == "System.Double");
```

#### `Il2Cpp.String`
```ts
const str = Il2Cpp.String.from("Hello!");

assert(str.content == "Hello!");

str.content = "Bye";
assert(str.content == "Bye");

assert(str.length == 3);
assert(str.content?.length == 3);

assert(str.object.class.type.name == "System.String");
assert(str.object.class.type.typeEnum == "string");
```

#### `Il2Cpp.Type`
```ts
const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

const Int32Class = mscorlib.classes["System.Int32"];
const StringClass = mscorlib.classes["System.String"];
const ObjectClass = mscorlib.classes["System.Object"];

assert(StringClass.type.class.handle.equals(StringClass.handle));

const array = Il2Cpp.Array.from<number>(Int32Class, [0, 1, 2, 3, 4]);
assert(array.object.class.type.name == "System.Int32[]");
assert(array.object.class.type.dataType?.name == "System.Int32");

assert(StringClass.type.name == "System.String");

assert(Int32Class.type.typeEnum == "i4");
assert(ObjectClass.type.typeEnum == "object");
```

#### `Il2Cpp.ValueType`
```ts
const coreModule = Il2Cpp.Domain.reference.assemblies["UnityEngine.CoreModule"].image;

const Vector2Class = coreModule.classes["UnityEngine.Vector2"];

const vec = Vector2Class.fields.positiveInfinityVector.value as Il2Cpp.ValueType;

assert(vec.class.type.name == "UnityEngine.Vector2");

assert(vec.fields.x.value == Infinity);
assert(vec.fields.y.value == Infinity);
```