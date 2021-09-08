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
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;
const SystemString = mscorlib.classes["System.String"];

const arr = Il2Cpp.Array.from<Il2Cpp.String>(SystemString, [
    Il2Cpp.String.from("One"), Il2Cpp.String.from("Two"), Il2Cpp.String.from("Three")
]);

console.log(arr.elementSize == StringClass.arrayElementSize);

console.log(arr.length == 3);

console.log(arr.object.class.type.name == "System.String[]");

console.log(arr.elementType.name == "System.String");

console.log(Array.from(arr).join(",") == "One,Two,Three");

console.log(arr.get(0).content == "One");
arr.set(0, Il2Cpp.String.from("Replaced"));
console.log(arr.get(0).content == "Replaced");
```

##### `Il2Cpp.Assembly`
```ts
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;

console.log(mscorlib.name == "mscorlib");
```

##### `Il2Cpp.Class`
```ts
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;

const BooleanClass = mscorlib.classes["System.Boolean"];
const Int32Class = mscorlib.classes["System.Int32"];
const Int64Class = mscorlib.classes["System.Int64"];
const ObjectClass = mscorlib.classes["System.Object"];
const DayOfWeekClass = mscorlib.classes["System.DayOfWeek"];
const MathClass = mscorlib.classes["System.Math"];
const IFormattableClass = mscorlib.classes["System.IFormattable"];
const ExecutionContextClass = mscorlib.classes["System.Threading.ExecutionContext"];
const ExecutionContextFlagsClass = mscorlib.classes["System.Threading.ExecutionContext.Flags"];

console.log(BooleanClass.arrayClass.name == "Boolean[]");

console.log(Int32Class.arrayElementSize == 4);
console.log(Int64Class.arrayElementSize == 8);
console.log(ObjectClass.arrayElementSize == Process.pointerSize);

console.log(BooleanClass.arrayClass.elementClass?.name == "Boolean");

console.log(ExecutionContextFlagsClass.declaringClass!.handle.equals(ExecutionContextClass.handle));

console.log(Int32Class.hasStaticConstructor == ".cctor" in Int32Class.methods);

console.log(Int32Class.image.name == "mscorlib.dll");

console.log(DayOfWeekClass.isEnum);
console.log(!ObjectClass.isEnum);

console.log(IFormattableClass.isInterface);
console.log(!ObjectClass.isInterface);

if (!MathClass.isStaticConstructorFinished) {
 MathClass.initialize();
 console.log(MathClass.isStaticConstructorFinished);
}

console.log(Int32Class.isValueType);
console.log(!ObjectClass.isValueType);

console.log(BooleanClass.name == "Boolean");

console.log(BooleanClass.namespace == "System");

console.log(BooleanClass.parent!.type.name == "System.ValueType");
console.log(ObjectClass.parent == null);

console.log(BooleanClass.type.name == "System.Boolean");
```

#### `Il2Cpp.Domain`
```ts
console.log(Il2Cpp.Domain.reference.name == "IL2CPP Root Domain");
```

#### `Il2Cpp.Field`
```ts
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;
const coreModule = Il2Cpp.Domain.reference.assemblies["UnityEngine.CoreModule"].image;

const BooleanClass = mscorlib.classes["System.Boolean"];
const MathClass = mscorlib.classes["System.Math"];
const ThreadClass = mscorlib.classes["System.Threading.Thread"];
const Vector2Class = coreModule.classes["UnityEngine.Vector2"];

console.log(MathClass.fields.PI.class.handle.equals(MathClass.handle));

console.log(!Vector2Class.fields.x.isStatic);
console.log(Vector2Class.fields.oneVector.isStatic);

console.log(MathClass.fields.PI.isLiteral);

console.log(ThreadClass.fields.current_thread.isThreadStatic);
console.log(!ThreadClass.fields.m_Delegate.isThreadStatic);

console.log(BooleanClass.fields.TrueLiteral.name == "TrueLiteral");

console.log(MathClass.fields.PI.type.name == "System.Double");

const vec = Vector2Class.fields.oneVector.value as Il2Cpp.ValueType;
console.log(vec.fields.x.value == 1);
console.log(vec.fields.y.value == 1);

vec.fields.x.value = 42;
console.log(vec.fields.x.value == 42);
```

#### `Il2Cpp.Image`
```ts
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;

console.log(mscorlib.name == "mscorlib.dll");
```

#### `Il2Cpp.Method`
```ts
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;

const BooleanClass = mscorlib.classes["System.Boolean"];
const ArrayClass = mscorlib.classes["System.Array"];
const MathClass = mscorlib.classes["System.Math"];

console.log(MathClass.methods.Sqrt.class.handle.equals(MathClass.handle));

console.log(ArrayClass.methods.Empty.isGeneric);

console.log(!BooleanClass.methods.ToString.isStatic);
console.log(!BooleanClass.methods.Parse.isStatic);

console.log(MathClass.methods.Sqrt.name == "Sqrt");

console.log(MathClass.methods[".cctor"].parameterCount == 0);
console.log(MathClass.methods.Abs.parameterCount == 1);
console.log(MathClass.methods.Max.parameterCount == 2);

console.log(BooleanClass.methods.Parse.invoke<boolean>(Il2Cpp.String.from("true")));

MathClass.methods.Max.implementation = (_instance, parameters) => {
 const val1 = parameters.val1.value as number;
 const val2 = parameters.val2.value as number;
 return val1 > val2 ? val2 : val1;
};
console.log(MathClass.methods.Max.invoke<number>(1, 2) == 1);

MathClass.methods.Max.implementation = null;
console.log(MathClass.methods.Max.invoke<number>(1, 2) == 2);

MathClass.methods.Max.intercept({
 onEnter(_instance, parameters) {
  parameters.val1.value = 10;
 }
});
console.log(MathClass.methods.Max.invoke<number>(1, 2) == 10);
```

#### `Il2Cpp.Object`
```ts
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;
const coreModule = Il2Cpp.Domain.reference.assemblies["UnityEngine.CoreModule"].image;

const OrdinalComparerClass = mscorlib.classes["System.OrdinalComparer"];
const Vector2Class = coreModule.classes["UnityEngine.Vector2"];

const ordinalComparer = Il2Cpp.Object.from(OrdinalComparerClass);
console.log(ordinalComparer.class.name == "OrdinalComparer");
console.log(ordinalComparer.base.class.name == "StringComparer");

const vec = Il2Cpp.Object.from(Vector2Class);
vec.methods[".ctor"].invoke(36, 4);

const vecUnboxed = vec.unbox();
console.log(vec.fields.x.value == vecUnboxed.fields.x.value);
console.log(vec.fields.y.value == vecUnboxed.fields.y.value);

const vecBoxed = vecUnboxed.box();
console.log(vecBoxed.fields.x.value == vecUnboxed.fields.x.value);
console.log(vecBoxed.fields.y.value == vecUnboxed.fields.y.value);

console.log(!vecBoxed.handle.equals(vec.handle));
```

#### `Il2Cpp.Parameter`
```ts
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;

const dParameter = mscorlib.classes["System.Math"].methods.Sqrt.parameters.d;

console.log(dParameter.name == "d");

console.log(dParameter.position == 0);

console.log(dParameter.type.name == "System.Double");
```

#### `Il2Cpp.String`
```ts
const str = Il2Cpp.String.from("Hello!");

console.log(str.content == "Hello!");

str.content = "Bye";
console.log(str.content == "Bye");

console.log(str.length == 3);
console.log(str.content?.length == 3);

console.log(str.object.class.type.name == "System.String");
console.log(str.object.class.type.typeEnum == "string");
```

#### `Il2Cpp.Type`
```ts
const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;

const Int32Class = mscorlib.classes["System.Int32"];
const StringClass = mscorlib.classes["System.String"];
const ObjectClass = mscorlib.classes["System.Object"];

console.log(StringClass.type.class.handle.equals(StringClass.handle));

const array = Il2Cpp.Array.from<number>(Int32Class, [0, 1, 2, 3, 4]);
console.log(array.object.class.type.name == "System.Int32[]");
console.log(array.object.class.type.dataType?.name == "System.Int32");

console.log(StringClass.type.name == "System.String");

console.log(Int32Class.type.typeEnum == "i4");
console.log(ObjectClass.type.typeEnum == "object");
```

#### `Il2Cpp.ValueType`
```ts
const coreModule = Il2Cpp.Domain.reference.assemblies["UnityEngine.CoreModule"].image;

const Vector2Class = coreModule.classes["UnityEngine.Vector2"];

const vec = Vector2Class.fields.positiveInfinityVector.value as Il2Cpp.ValueType;

console.log(vec.class.type.name == "UnityEngine.Vector2");

console.log(vec.fields.x.value == Infinity);
console.log(vec.fields.y.value == Infinity);
```
