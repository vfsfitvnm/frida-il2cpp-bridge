# frida-il2cpp-bridge

[![Frida](https://img.shields.io/badge/frida-ef6456?link=https://frida.re/&style=for-the-badge&logo=data:image/x-icon;base64,AAABAAIAICAAAAEAIACoEAAAJgAAABAQAAABACAAaAQAAM4QAAAoAAAAIAAAAEAAAAABACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////AP///0D//////////////////////////////////////////////2D///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///0D/////////////////////////////////////////gP///wD///8A////AP///4//////////////////////////////////////////7////xD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////QP////////////////////////////////////////+A////AP///wD///8A////EP///9//////////////////////////////////////////gP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///9A/////////////////////////////////////////4D///8A////AP///wD///8A////UP//////////////////////////////////////////////IP///wD///8A////AP///wD///8A////AP///wD///8A////AP///0D/////////////////////////////////////////gP///wD///8A////AP///wD///8A////r/////////////////////////////////////////+v////AP///wD///8A////AP///wD///8A////AP///wD///8A////QP////////////////////////////////////////+A////AP///wD///8A////AP///wD///8Q////7/////////////////////////////////////////9A////AP///wD///8A////AP///wD///8A////AP///wD///9A/////////////////////////////////////////4D///8A////AP///wD///8A////AP///wD///9g/////////////////////////////////////////8////8A////AP///wD///8A////AP///wD///8A////AP///0D/////////////////////////////////////////gP///wD///8A////AP///wD///8A////AP///wD///+//////////////////////////////////////////2D///8A////AP///wD///8A////AP///wD///8A////QP////////////////////////////////////////+A////AP///wD///8A////AP///wD///8A////AP///yD////v////////////////////////////////////7////xD///8A////AP///wD///8A////AP///wD///9A/////////////////////////////////////////4D///8A////AP///wD///8A////AP///wD///8A////AP///3D/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////gP///wD///8A////AP///wD///8A////AP///wD///8A////EP///9////////////////////////////////////////////////////////////////////////////////////////////////////////////////////+A////AP///wD///8A////AP///wD///8A////AP///1D////v/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////4D///8A////AP///wD///8A////AP///wD///9g////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////gP///wD///8A////AP///wD///8A////YP////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////+A////AP///wD///8A////AP///yD////v/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////4D///8A////AP///wD///8A////n/////////////////////////////////////////////////////////+/////v////7////+/////v////7////+/////v////8//////////////////////////////////////////gP///wD///8A////AP///wD////v/////////////////////////////////////////8////9Q////AP///wD///8A////AP///wD///8A////AP///wD///8A////QP////////////////////////////////////////+A////AP///wD///8A////QP////////////////////////////////////////+v////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///9A/////////////////////////////////////////4D///8A////AP///wD///+A/////////////////////////////////////////xD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///0D/////////////////////////////////////////gP///wD///8A////AP///4D///////////////////////////////////+/////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////QP////////////////////////////////////////+A////AP///wD///8A////v////////////////////////////////////4D///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///9A/////////////////////////////////////////4D///8A////AP///wD///+/////////////////////////////////////gP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///0D/////////////////////////////////////////gP///wD///8A////AP///4D///////////////////////////////////+/////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////QP////////////////////////////////////////+A////AP///wD///8A////gP////////////////////////////////////////8g////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///9A/////////////////////////////////////////4D///8A////AP///wD///8w/////////////////////////////////////////8////8Q////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///0D/////////////////////////////////////////gP///wD///8A////AP///wD////f/////////////////////////////////////////9////9g////IP///wD///8A////AP///wD///8A////AP///wD///8A////QP////////////////////////////////////////+A////AP///wD///8A////AP///4D//////////////////////////////////////////////////////////////9////+/////v////7////+/////v////7/////P/////////////////////////////////////////4D///8A////AP///wD///8A////AP///8//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////gP///wD///8A////AP///wD///8A////IP///+////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////+A////AP///wD///8A////AP///wD///8A////IP///8///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////4D///8A////AP///wD///8A////AP///wD///8A////AP///2D////f////////////////////////////////////////////////////////////////////////////////////////////////////////////////////gP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///9Q////j////7/////v//////////////////////////////////////////////////////////////////////////////////////////////+A////AIAf/AHAD/wBwA/8AeAH/AHwB/wB8AP8AfgD/AH8AfwB/AD8Af4AAAH+AAAB/AAAAfgAAAHwAAAB4AAAAeAAAAHgB/wBwB/8AcAf/AHAP/wBwD/8AcA//AHAP/wBwB/8AcAP/AHgA/wB4AAAAfAAAAHwAAAB+AAAAf4AAAH/gAABKAAAABAAAAAgAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///yD////v////////////////////cP///wD///8A////AP///wD///8A////v////////////////////0D///8A////cP///////////////////+////8Q////AP///wD///8A////AP///7////////////////////9A////AP///wD///+/////////////////////j////wD///8A////AP///wD///+/////////////////////QP///wD///8A////IP////////////////////////8g////AP///wD///8A////v////////////////////0D///8A////AP///wD///+A////////////////////z////4D///+A////gP///9////////////////////9A////AP///wD///8A////cP//////////////////////////////////////////////////////////////QP///wD///8A////n////////////////////////////////////////////////////////////////////0D///8A////QP////////////////////////////////////////////////////////////////////////9A////AP///5////////////////////+v////IP///wD///8A////AP///wD///+/////////////////////QP///wD///+/////////////////////EP///wD///8A////AP///wD///8A////v////////////////////0D///8A////////////////////v////wD///8A////AP///wD///8A////AP///7////////////////////9A////AP///7////////////////////8Q////AP///wD///8A////AP///wD///+/////////////////////QP///wD///+f////////////////////z////zD///8A////AP///wD///8A////v////////////////////0D///8A////MP////////////////////////////////////////////////////////////////////////9A////AP///wD///9g////////////////////////////////////////////////////////////////////QP///wD///8A////AP///yD///+f////7////////////////////////////////////////////////////0AD4AAAgeAAAMHgAADA4AAA4AAAAOAAAADAAAAAgAAAAIHgAACD4AAAh+AAAIPgAACB4AAAgAAAAMAAAADgAAAA)](https://frida.re)
[![NPM](https://img.shields.io/npm/v/frida-il2cpp-bridge?label=&logo=npm&style=for-the-badge)](https://npmjs.org/package/frida-il2cpp-bridge)

[Frida](https://frida.re/) module to dump, manipulate and hijack any IL2CPP application at runtime with a high level
 of abstraction, without needing the `global-metadata.dat` file.

```ts
import { Il2Cpp } from "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();
    
    const TestAssembly = Il2Cpp.domain.assemblies["Test.Assembly"].image;
    
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

### Snippets
* [`Initialization`](#initialization)
* [`Dump`](#dump)
* [`Print all the strings on the heap`](#print-all-strings)
* [`Find every instance of a certain class`](#find-instances)
* [`Class tracing`](#class-tracing)
* [`Method tracing`](#method-tracing)
* [`Method replacement`](#method-replacement)
* [`Method interception`](#method-interception)

##### Initialization
```ts
import { Il2Cpp } from "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();
    
    // Uncomment for REPL access
    // (global as any).Il2Cpp = Il2Cpp;
}

main().catch(error => console.log(error.stack));
```

##### Dump
Make sure the target has write permissions to the destination.
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
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const TypeClass = corlib.classes["System.Type"];

Il2Cpp.GC.choose(TypeClass).forEach(instance => {
    // Do whatever you want
    assert(instance.class.type.name == "System.Type");
});
```
Alternatively
```ts
const TypeArrayClass = corlib.classes["System.Type"].arrayClass;

Il2Cpp.GC.choose2<Il2Cpp.Array<Il2Cpp.Object>>(TypeArrayClass).forEach(instance => {
    // Do whatever you want
    assert(instance.class.type.name == "System.Type[]");
});
```

##### Print all strings
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const StringClass = corlib.classes["System.String"];

Il2Cpp.GC.choose<Il2Cpp.String>(StringClass).forEach(str => {
    console.log(str.handle, str.content);
});
```

##### Class tracing
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const StringClass = corlib.classes["System.String"];

StringClass.trace();
```
It will log something like:
```coffeescriptliterate
[il2cpp] 0x015ed550 get_Chars
[il2cpp] 0x005602f0 FastAllocateString
[il2cpp] 0x00ab497c wstrcpy
[il2cpp] 0x01a62bc0 IsNullOrEmpty
[il2cpp] 0x015ed550 get_Chars
[il2cpp] 0x015ed550 get_Chars
````

##### Method tracing
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const IsNullOrEmpty = corlib.classes["System.String"].methods.IsNullOrEmpty;

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
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const IsNullOrEmpty = corlib.classes["System.String"].methods.IsNullOrEmpty;

IsNullOrEmpty.implementation = (instance, parameters) => {
    parameters.value.value = Il2Cpp.String.from("Hello!");
    return false;
};
```

Later on, to revert the replacement
```ts
IsNullOrEmpty.implementation = null;
```


##### Method interception
You can replace any of the parameters and the return value by reassigning them.
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const StringClass = corlib.classes["System.String"];

StringClass.methods.IsNullOrEmpty.intercept({
    onEnter(instance, parameters) {
        console.log(parameters.value.value);
    },
    onLeave(returnValue) {
        returnValue.value = !(returnValue.value as boolean);
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
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const StringClass = corlib.classes["System.String"];

const arr = Il2Cpp.Array.from<Il2Cpp.String>(StringClass, [
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
const corlib = Il2Cpp.domain.assemblies.mscorlib;

assert(corlib.name == "mscorlib");
```

##### `Il2Cpp.Class`
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;

const BooleanClass = corlib.classes["System.Boolean"];
const Int32Class = corlib.classes["System.Int32"];
const Int64Class = corlib.classes["System.Int64"];
const ObjectClass = corlib.classes["System.Object"];
const DayOfWeekClass = mscorlib.classes["System.DayOfWeek"];
const MathClass = mscorlib.classes["System.Math"];
const IFormattableClass = mscorlib.classes["System.IFormattable"];
const ExecutionContextClass = mscorlib.classes["System.Threading.ExecutionContext"];
const ExecutionContextFlagsClass = mscorlib.classes["System.Threading.ExecutionContext.Flags"];

assert(BooleanClass.arrayClass.name == "Boolean[]");

assert(Int32Class.arrayElementSize == 4);
assert(Int64Class.arrayElementSize == 8);
assert(ObjectClass.arrayElementSize == Process.pointerSize);

assert(BooleanClass.arrayClass.elementClass.name == "Boolean");

assert(ExecutionContextFlagsClass.declaringClass!.handle.equals(ExecutionContextClass.handle));

assert(Int32Class.hasStaticConstructor == ".cctor" in Int32Class.methods);

assert(Int32Class.image.name == "mscorlib.dll");

assert(DayOfWeekClass.isEnum);
assert(!ObjectClass.isEnum);

assert(IFormattableClass.isInterface);
assert(!ObjectClass.isInterface);

if (!MathClass.isStaticConstructorFinished) {
 MathClass.ensureInitialized();
 assert(MathClass.isStaticConstructorFinished);
}

assert(Int32Class.isStruct);
assert(!ObjectClass.isStruct);

assert(BooleanClass.name == "Boolean");

assert(BooleanClass.namespace == "System");

assert(BooleanClass.parent!.type.name == "System.ValueType");
assert(ObjectClass.parent == null);

assert(BooleanClass.type.name == "System.Boolean");
```

#### `Il2Cpp.Domain`
```ts
assert(Il2Cpp.domain.name == "IL2CPP Root Domain");
```

#### `Il2Cpp.Field`
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const coreModule = Il2Cpp.domain.assemblies["UnityEngine.CoreModule"].image;

const BooleanClass = corlib.classes["System.Boolean"];
const MathClass = corlib.classes["System.Math"];
const ThreadClass = corlib.classes["System.Threading.Thread"];
const Vector2Class = coreModule.classes["UnityEngine.Vector2"];

assert(MathClass.fields.PI.class.handle.equals(MathClass.handle));

assert(Vector2Class.fields.x.isInstance);
assert(!Vector2Class.fields.oneVector.isInstance);

assert(MathClass.fields.PI.isLiteral);

assert(ThreadClass.fields.current_thread.isThreadStatic);
assert(!ThreadClass.fields.m_Delegate.isThreadStatic);

assert(BooleanClass.fields.TrueLiteral.name == "TrueLiteral");

assert(MathClass.fields.PI.type.name == "System.Double");

const vec = Vector2Class.fields.oneVector.value as _Il2CppValueType;
assert(vec.fields.x.value == 1);
assert(vec.fields.y.value == 1);

vec.fields.x.value = 42;
assert(vec.fields.x.value == 42);
```

#### `Il2Cpp.Image`
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;

assert(corlib.name == "mscorlib.dll");
```

#### `Il2Cpp.Method`
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;

const BooleanClass = corlib.classes["System.Boolean"];
const ArrayClass = corlib.classes["System.Array"];
const MathClass = corlib.classes["System.Math"];

assert(MathClass.methods.Sqrt.class.handle.equals(MathClass.handle));

assert(ArrayClass.methods.Empty.isGeneric);

assert(BooleanClass.methods.ToString.isInstance);
assert(!BooleanClass.methods.Parse.isInstance);

assert(MathClass.methods.Sqrt.name == "Sqrt");

assert(MathClass.methods[".cctor"].parameterCount == 0);
assert(MathClass.methods.Abs.parameterCount == 1);
assert(MathClass.methods.Max.parameterCount == 2);

assert(BooleanClass.methods.Parse.invoke<boolean>(_Il2CppString.from("true")));

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
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;
const coreModule = Il2Cpp.domain.assemblies["UnityEngine.CoreModule"].image;

const OrdinalComparerClass = corlib.classes["System.OrdinalComparer"];
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
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;

const dParameter = corlib.classes["System.Math"].methods.Sqrt.parameters.d;

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
assert(str.object.class.type.typeEnum == Il2Cpp.TypeEnum.STRING);
```

#### `Il2Cpp.Type`
```ts
const corlib = Il2Cpp.domain.assemblies.mscorlib.image;

const Int32Class = corlib.classes["System.Int32"];
const StringClass = corlib.classes["System.String"];
const ObjectClass = corlib.classes["System.Object"];

assert(StringClass.type.class.handle.equals(StringClass.handle));

const array = Il2Cpp.Array.from<number>(Int32Class, [0, 1, 2, 3, 4]);
assert(array.object.class.type.name == "System.Int32[]");
assert(array.object.class.type.dataType?.name == "System.Int32");

assert(StringClass.type.name == "System.String");

assert(Int32Class.type.typeEnum == Il2Cpp.TypeEnum.I4);
assert(ObjectClass.type.typeEnum == Il2Cpp.TypeEnum.OBJECT);
```

#### `Il2Cpp.ValueType`
```ts
const coreModule = Il2Cpp.domain.assemblies["UnityEngine.CoreModule"].image;

const Vector2Class = coreModule.classes["UnityEngine.Vector2"];

const vec = Vector2Class.fields.positiveInfinityVector.value as Il2Cpp.ValueType;

assert(vec.class.type.name == "UnityEngine.Vector2");

assert(vec.fields.x.value == Infinity);
assert(vec.fields.y.value == Infinity);
```