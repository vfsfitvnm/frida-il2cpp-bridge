# frida-il2cpp-bridge

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
const SystemString = mscorlib.classes["System.String"];

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
