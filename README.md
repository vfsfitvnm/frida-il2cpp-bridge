# frida-il2cpp-bridge
[Frida](https://frida.re/) module to dump, manipulate and hijack any IL2CPP application at runtime with a high level of abstraction.
```typescript
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();

    const domain = await Il2Cpp.Domain.get();
    
    const TestAssembly = domain.assemblies["Test.Assembly"].image;
    
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
It **should** support Unity versions from `5.3.0` to `2020.2.0`. I couldn't test them
all, please file a bug in case something doesn't work as expected. Thanks to [Il2CppInspector](https://github.com/djkaty/Il2CppInspector)
for providing the headers.

### Platform support
- [ ] Linux _(not tested)_
- [x] Android
- [ ] Windows _(missing test device and [early instrumentation](src/utils/platform.ts) knowledge)_
- [ ] iOS _(missing test device and [early instrumentation](src/utils/platform.ts) knowledge)_

### Installation
```shell script
npm install --save-dev frida-il2cpp-bridge
```
You _may_ need to include `"moduleResolution": "node"` in your `tsconfig.json`.

### Changelog
- 0.1.4 Added few snippets.
- 0.1.3 `Il2Cpp.ValueType`, `Il2Cpp.Object` and `Il2Cpp.String` can now have a `NULL` handle.
- 0.1.1 Added `Il2Cpp.choose`, `Il2Cpp.Image.getClassFromName`, `Il2Cpp.Class.arrayClass`.
`Il2Cpp.Class.ensureInitialized` will now call the api `il2cpp_runtime_class_init`.
- 0.1.0 Initial release.

### Snippets
First things first: read the [docs](https://vfsfitvnm.github.io/frida-il2cpp-bridge/index.html).
* [`Initialization`](#initialization)
* [`Dump`](#dump)
* [`Print all the strings on the heap`](#print-all-strings)
* [`Find every instance of a certain class`](#find-instances)
* [`String manipulation`](#string-manipulation)
* [`Array manipulation`](#array-manipulation)
* [`Class tracing`](#class-tracing)
* [`Method interception`](#method-interception)

##### Initialization
```typescript
import "frida-il2cpp-bridge";

async function main() {
    await Il2Cpp.initialize();
    const domain = await Il2Cpp.Domain.get();
}

main().catch(error => console.log(error.stack));
```

##### Dump
```typescript
Il2Cpp.dump(`/full/path/to/file.cs`);
```
This will produce something like:
```cs
// mscorlib.dll
struct System.Int32
{
    static System.Int32 MaxValue; // 0x0
    static System.Int32 MinValue; // 0x0
    System.Int32 m_value; // 0x10

    System.Boolean System.IConvertible.ToBoolean(System.IFormatProvider provider); // 0x00a8ef1e
    System.Byte System.IConvertible.ToByte(System.IFormatProvider provider); // 0x00ff3228
    System.Char System.IConvertible.ToChar(System.IFormatProvider provider); // 0x00cf8ab9
    System.DateTime System.IConvertible.ToDateTime(System.IFormatProvider provider); // 0x009ee401
    // ....
}
```

##### Find instances
```typescript
Il2Cpp.choose(YourClass).forEach(instance => {
    // Do whatever you want
});
```

##### Print all strings
```typescript
const corlib = domain.assemblies.mscorlib.image;
const StringClass = corlib.classes["System.String"];

Il2Cpp.choose<Il2Cpp.String>(StringClass).forEach(str => {
    console.log(str.handle, str.content);
});
```

##### String manipulation
```typescript
const str = Il2Cpp.String.from("Hello");
console.log(str, str.length); // Hello 5

str.content = "Goodbye";
console.log(str, str.length); // Goodbye 7
```

##### Array manipulation
It's not possible to add or remove an array element at the moment.
```typescript
const corlib = domain.assemblies.mscorlib.image;
const StringClass = corlib.classes["System.String"];

const arr = Il2Cpp.Array.from<Il2Cpp.String>(StringClass, [
    Il2Cpp.String.from("One"), Il2Cpp.String.from("Two"), Il2Cpp.String.from("Three")
]);

console.log(arr.length); // 3
for (const str of arr) {
    console.log(str); // One .. Two .. Three
}

arr.set(0, Il2Cpp.String.from("Zero"));
console.log(arr.get(0)); // Zero
```

##### Class tracing
```typescript
const corlib = domain.assemblies.mscorlib.image;
const StringClass = corlib.classes["System.String"];

StringClass.trace();
```
It will log something like:
```shell script
[il2cpp] 0x015ed550 get_Chars
[il2cpp] 0x005602f0 FastAllocateString
[il2cpp] 0x00ab497c wstrcpy
[il2cpp] 0x01a62bc0 IsNullOrEmpty
[il2cpp] 0x015ed550 get_Chars
[il2cpp] 0x015ed550 get_Chars
````
You can trace single methods as well.

##### Method interception
You can replace any of the parameters and the return value by reassigning them.
```typescript
const corlib = domain.assemblies.mscorlib.image;
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


