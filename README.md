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
- 0.1.0 _Initial release._

### API
Read the [docs](https://vfsfitvnm.github.io/frida-il2cpp-bridge/index.html).
