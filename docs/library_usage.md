# Library Usage

### Snippets
This section provides practical code examples for common tasks you can perform with `frida-il2cpp-bridge`.

* [`Initialization`](#initialization)
* [`Dump`](#dump)
* [`Find every instance of a certain class`](#find-instances)
* [`Class tracing`](#class-tracing)
* [`Method tracing`](#method-tracing)
* [`Method replacement`](#method-replacement)
* [`Method interception`](#method-interception)

##### Initialization
The `Il2Cpp.initialize()` method is crucial for setting up the bridge. It performs the following steps:
1.  **Locates the Il2Cpp Module**: It searches for the main Il2Cpp native library (e.g., `libil2cpp.so` on Android, `GameAssembly.dll` on Windows). It can be configured via `Il2Cpp.$config.moduleName` if the default names are not suitable. If the module isn't loaded yet, it will wait for it to load.
2.  **Waits for Il2Cpp Runtime Initialization**: Once the module is found, it ensures that the Il2Cpp runtime itself is fully initialized by the game. It does this by checking a core Il2Cpp function (`il2cpp_get_corlib`) and, if necessary, intercepting the Il2Cpp initialization function (`il2cpp_init`) to wait for its completion.

Typically, you'll call `Il2Cpp.initialize()` at the beginning of your agent script. While `Il2Cpp.initialize()` can be called directly, it's often implicitly handled by `Il2Cpp.perform()`, which is the recommended way to ensure your code runs in a safe context.

```typescript
import "frida-il2cpp-bridge";

async function main() {
    // Explicit initialization (optional if using Il2Cpp.perform)
    await Il2Cpp.initialize(); 

    // Example: Get the Il2Cpp domain
    const domain = Il2Cpp.Domain.reference;
    console.log(`Il2Cpp Domain: ${domain.name}`);
    
    // ... your agent code ...
}

// It's common to wrap your main logic in Il2Cpp.perform
async function mainWithPerform() {
    await Il2Cpp.perform(async () => {
        // Il2Cpp.initialize() is implicitly called by Il2Cpp.perform()
        const domain = Il2Cpp.Domain.reference;
        console.log(`Il2Cpp Domain: ${domain.name}`);

        // ... your agent code ...
    });
}

main().catch(error => console.error(error.stack));
// or
// mainWithPerform().catch(error => console.error(error.stack));
```
The `Il2Cpp.initialize(blocking?: boolean)` method takes an optional boolean parameter. This parameter is mainly for internal use by `Il2Cpp.perform` to handle execution on the main thread. For most user scripts, calling `await Il2Cpp.initialize()` without parameters or relying on `Il2Cpp.perform` is sufficient.

For advanced scenarios, you can override default behaviors using `Il2Cpp.$config`. For example, set `Il2Cpp.$config.moduleName = "CustomModule.dll";` or `Il2Cpp.$config.unityVersion = "2020.1.1f1";` *before* `Il2Cpp.perform()` or `Il2Cpp.initialize()` if auto-detection fails.

The optional `flag` parameter in `Il2Cpp.perform(block, flag)` controls thread attachment behavior:
*   `"bind"` (default): Attaches the current thread to Il2Cpp if not already attached, and binds its lifetime to the global script object (detaches when script is unloaded).
*   `"free"`: Attaches if needed, but the thread must be manually detached using `thread.detach()` if it was newly attached.
*   `"leak"`: Attaches if needed, and never detaches (use with caution).
*   `"main"`: Schedules the `block` to be executed on the Il2Cpp main thread. Example: `await Il2Cpp.perform(() => { console.log("Running on main thread!"); }, "main");`

##### Dump
**Note:** `Il2Cpp.dump()` is deprecated. Please use the CLI command `npx frida-il2cpp-bridge dump` for more robust dumping capabilities.

The `Il2Cpp.dump()` function generates a pseudo-C# file containing information about all loaded Il2Cpp assemblies, classes, methods, fields, and their memory addresses. This is extremely useful for offline analysis and understanding the structure of the target application.

Make sure the target application has write permissions to the destination path if you specify one.

```typescript
import "frida-il2cpp-bridge";

async function dumpApplication() {
    await Il2Cpp.perform(async () => {
        // Option 1: Specify a full path for the dump file.
        // Ensure the application has write permissions to this path.
        // Il2Cpp.dump("/data/local/tmp/dump.cs"); 

        // Option 2: Let the bridge automatically determine the path.
        // On Android, this might be something like:
        // /storage/emulated/0/Android/data/com.example.application/files/com.example.application_1.2.3.cs
        Il2Cpp.dump(); 
        console.log("Dump complete!");
    });
}

dumpApplication().catch(error => console.error(error.stack));
```

The output file (`dump.cs` or similar) will look something like this:
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
You can find all live instances of a specific class in the application's memory. This is useful for examining object states or finding specific game objects. There are two main approaches:

**1. Using `Il2Cpp.GC.choose` (Live Objects):**
This method iterates over objects currently managed by the Il2Cpp Garbage Collector (GC) and returns instances of the specified class. This is a live operation and reflects the current state of the application.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available, e.g. from node's assert module

async function findLiveInstances() {
    await Il2Cpp.perform(async () => {
        // Get a reference to the mscorlib image (where System.Type is defined)
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        // Get the Il2Cpp.Class object for System.Type
        const SystemType = mscorlib.classes["System.Type"];

        if (!SystemType) {
            console.error("System.Type class not found!");
            return;
        }

        console.log(`Searching for instances of ${SystemType.name}...`);
        const instances = Il2Cpp.GC.choose(SystemType);
        
        instances.forEach(instance => {
            // 'instance' is an Il2Cpp.Object representing an instance of System.Type
            console.log(`Found an instance of System.Type at ${instance.handle}`);
            // You can now inspect its fields or call its methods
            assert(instance.class.equals(SystemType)); 
        });
        console.log(`Found ${instances.length} instances.`);
    });
}

findLiveInstances().catch(error => console.error(error.stack));
```

**2. Using `Il2Cpp.MemorySnapshot` (Point-in-Time Snapshot):**
This method involves taking a snapshot of the Il2Cpp managed memory. You can then iterate over all objects in this snapshot and filter them. This is useful for analyzing the memory state at a specific moment or for more complex queries.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function findInstancesInSnapshot() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        // Let's find instances of System.String this time
        const SystemString = mscorlib.classes["System.String"];

        if (!SystemString) {
            console.error("System.String class not found!");
            return;
        }

        console.log(`Taking memory snapshot to find instances of ${SystemString.name}...`);
        // Create a memory snapshot
        const snapshot = new Il2Cpp.MemorySnapshot();

        // Filter objects in the snapshot that are exactly of type System.String
        const stringInstances = snapshot.objects.filter(o => o.class.equals(SystemString));
        // Alternative using built-in filter for exact match:
        // const stringInstances = snapshot.objects.filter(Il2Cpp.Filtering.IsExactly(SystemString));


        stringInstances.forEach(instance => {
            // 'instance' is an Il2Cpp.Object (actually an Il2Cpp.String in this case)
            const strValue = new Il2Cpp.String(instance.handle).content;
            console.log(`Found a System.String instance at ${instance.handle} with value: "${strValue}"`);
            assert(instance.class.equals(SystemString));
        });
        console.log(`Found ${stringInstances.length} string instances in the snapshot.`);
    });
}

// findInstancesInSnapshot().catch(error => console.error(error.stack));
```

For safer usage, ensuring `free()` is called, you can use the `Il2Cpp.memorySnapshot(block)` helper:
```typescript
// (import assert from "assert";)
async function findInstancesWithHelper() {
    await Il2Cpp.perform(async () => {
        const SystemString = Il2Cpp.Domain.reference.assemblies.mscorlib.image.classes["System.String"];
        if (!SystemString) return;

        const count = Il2Cpp.memorySnapshot(snapshot => {
            // snapshot is an Omit<Il2Cpp.MemorySnapshot, "free">
            console.log(`Found ${snapshot.objects.length} total objects in snapshot.`);
            console.log(`Found ${snapshot.classes.length} initialized classes in snapshot.`);
            return snapshot.objects.filter(o => o.class.equals(SystemString)).length;
        });
        console.log(`Found ${count} string instances.`);
    });
}
// findInstancesWithHelper().catch(console.error);
```

##### Class tracing
You can trace all method calls for a specific class. This will log when any method in that class is entered and when it is exited. This is useful for understanding the behavior of a class in real-time.

The `.trace()` method is a convenient shortcut available on `Il2Cpp.Class` instances. It internally uses the `Il2Cpp.trace()` builder to set up tracing for all methods of that class.

```typescript
import "frida-il2cpp-bridge";

async function traceStringClass() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const SystemString = mscorlib.classes["System.String"];

        if (!SystemString) {
            console.error("System.String class not found!");
            return;
        }

        console.log(`Tracing all methods of ${SystemString.name}...`);
        // This will start logging calls to methods of System.String
        SystemString.trace(); 
        
        // To demonstrate, let's invoke a static method on System.String
        // (This requires finding a method and invoking it, which is more advanced for this snippet)
        // For example, if System.String.IsNullOrEmpty existed and was easy to call:
        // try {
        //    mscorlib.classes["System.String"].methods.IsNullOrEmpty.invoke(Il2Cpp.String.from("test"));
        // } catch(e) { console.error(e); }

        console.log("Tracing active. Interact with the application to see logs.");
        console.log("Tracing will stop when the script is detached or Frida is disconnected.");
        // To stop all tracing programmatically, you can use Interceptor.detachAll().
        // Note: This will detach ALL Frida interceptors, not just this specific trace.
        // setTimeout(() => {
        //     Interceptor.detachAll();
        //     console.log("All tracing stopped.");
        // }, 30000); // Stop after 30 seconds for example
    });
}

traceStringClass().catch(error => console.error(error.stack));
```
The console output will look something like this when methods of the traced class are called:
```
[il2cpp] 0x015ed550 get_Chars
[il2cpp] 0x005602f0 FastAllocateString
[il2cpp] 0x00ab497c wstrcpy
[il2cpp] 0x01a62bc0 IsNullOrEmpty
[il2cpp] 0x015ed550 get_Chars
[il2cpp] 0x015ed550 get_Chars
````

##### Method tracing
You can trace calls to a specific method. This is useful for focusing on the activity of a single function.

The `.trace()` method is a convenient shortcut available on `Il2Cpp.Method` instances. It uses the `Il2Cpp.trace()` builder to set up tracing for that particular method.

```typescript
import "frida-il2cpp-bridge";

async function traceSpecificMethod() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const SystemString = mscorlib.classes["System.String"];

        if (!SystemString) {
            console.error("System.String class not found!");
            return;
        }

        // Attempt to get the "IsNullOrEmpty" method
        // Note: Method names and signatures can vary. This is an example.
        // You might need to specify the parameter count if the method is overloaded.
        // e.g., SystemString.tryMethod("IsNullOrEmpty", 1);
        const isnullOrEmptyMethod = SystemString.tryMethod("IsNullOrEmpty"); 

        if (!isnullOrEmptyMethod) {
            console.error("System.String.IsNullOrEmpty method not found! Please check the method name and signature.");
            // As an alternative, let's try tracing 'ToString' if IsNullOrEmpty is not found.
            const toStringMethod = SystemString.tryMethod("ToString");
            if(toStringMethod){
                console.log(`Tracing ${SystemString.name}.${toStringMethod.name}()...`);
                toStringMethod.trace();
                 // Example: Create a string and call ToString on it
                const testString = Il2Cpp.String.from("Hello from Frida!");
                console.log("Calling ToString on a test string: " + testString.toString());
            } else {
                console.error("ToString method also not found on System.String.");
                return;
            }
        } else {
            console.log(`Tracing ${SystemString.name}.${isnullOrEmptyMethod.name}()...`);
            isnullOrEmptyMethod.trace();
            // Example: Invoke IsNullOrEmpty if found and it's static
            // This depends on the actual method signature and if it's static.
            // For a static IsNullOrEmpty(string):
            // isnullOrEmptyMethod.invoke(Il2Cpp.String.from("test"));
        }
        
        console.log("Tracing active for the specified method. Interact with the application to see logs.");
        // Tracing stops when the script detaches or via Interceptor.detachAll().
    });
}

traceSpecificMethod().catch(error => console.error(error.stack));
```
The console output for the traced method will look like:
```coffeescriptliterate
[il2cpp] 0x01a62bc0 IsNullOrEmpty
[il2cpp] 0x01a62bc0 IsNullOrEmpty
[il2cpp] 0x01a62bc0 IsNullOrEmpty
````

##### Method replacement
You can completely replace the implementation of an existing Il2Cpp method with your own JavaScript function. This is powerful for altering game logic, bypassing checks, or mocking functionality.

The `.implementation` property on an `Il2Cpp.Method` object allows you to set a new function. Setting it to `null` restores the original method.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function replaceMethodImplementation() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const MathClass = mscorlib.classes["System.Math"];

        if (!MathClass) {
            console.error("System.Math class not found!");
            return;
        }

        // Get the 'Max(int, int)' method. 
        // We need to specify parameter count for overloaded methods.
        // Assuming 'Max' that takes two integers.
        const maxMethod = MathClass.tryMethod("Max", 2); 

        if (!maxMethod) {
            console.error("System.Math.Max(int, int) method not found!");
            return;
        }

        // Save the original implementation if you need to call it later from your replacement
        const originalMax = maxMethod.implementation;

        console.log(`Replacing implementation of ${MathClass.name}.${maxMethod.name}...`);
        
        // Replace Max(a, b) to always return the smaller value instead of the larger one
        maxMethod.implementation = (instance, parameters) => {
            // 'instance' is null for static methods like Math.Max
            // 'parameters' is an object where keys are parameter names from the dump, 
            // or 'p0', 'p1', etc., if names are not available.
            // For Math.Max(int val1, int val2), parameters might be parameters.val1, parameters.val2
            // Or, more generically, access by order if names are uncertain:
            const val1 = parameters[0].value as number; // First parameter
            const val2 = parameters[1].value as number; // Second parameter
            
            console.log(`Custom Math.Max called with ${val1} and ${val2}. Returning the MINIMUM.`);
            return Math.min(val1, val2); // Return the minimum value
        };

        // Test the replacement
        // Note: Invoking directly like this is for testing the hook. 
        // The game itself will call the original Math.Max and hit your replacement.
        let result = maxMethod.invoke<number>(5, 10);
        console.log(`maxMethod.invoke(5, 10) returned: ${result}`);
        assert(result === 5, "Replacement did not return the minimum value!");

        // To call the original method from within your replacement (if needed):
        // maxMethod.implementation = (instance, parameters) => {
        //     const val1 = parameters[0].value as number;
        //     const val2 = parameters[1].value as number;
        //     if (val1 === 0 && val2 === 0) { // Some condition to trigger original
        //         return originalMax.call(instance, parameters[0], parameters[1]);
        //     }
        //     return Math.min(val1, val2);
        // };

        // Revert to the original implementation
        console.log("Reverting to original implementation...");
        maxMethod.implementation = null; // or maxMethod.implementation = originalMax;

        result = maxMethod.invoke<number>(5, 10);
        console.log(`maxMethod.invoke(5, 10) after revert returned: ${result}`);
        assert(result === 10, "Revert failed or original method did not return maximum!");
        
        console.log("Method replacement demonstration complete.");
    });
}

replaceMethodImplementation().catch(error => console.error(error.stack));
```

##### Method interception
Method interception allows you to execute custom code before (`onEnter`) and after (`onLeave`) a method runs, without completely replacing its original logic. This is useful for observing calls, modifying arguments on-the-fly, or changing the return value.

The `.intercept()` method on an `Il2Cpp.Method` object is used for this. It returns a `Frida.InterceptorListener` object, which you can use to `.detach()` the interceptor later if needed.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function interceptMethod() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const MathClass = mscorlib.classes["System.Math"];

        if (!MathClass) {
            console.error("System.Math class not found!");
            return;
        }

        const maxMethod = MathClass.tryMethod("Max", 2); // Max(int val1, int val2)

        if (!maxMethod) {
            console.error("System.Math.Max(int, int) method not found!");
            return;
        }

        console.log(`Intercepting ${MathClass.name}.${maxMethod.name}...`);

        const listener = maxMethod.intercept({
            onEnter(instance, parameters) {
                // 'instance' is null for static methods.
                // 'parameters' is an object where keys are param names or p0, p1, etc.
                // Let's change the first parameter to always be 100.
                const val1 = parameters[0].value as number;
                const val2 = parameters[1].value as number;
                console.log(`Original Math.Max called with: ${val1}, ${val2}`);
                
                parameters[0].value = 100; // Modify the first argument
                console.log(`Modified first parameter to: 100. Second parameter is: ${parameters[1].value}`);
            },
            onLeave(returnValue) {
                // 'returnValue' is an Il2Cpp.ValueHolder containing the original return value.
                const originalReturn = returnValue.value as number;
                console.log(`Original Math.Max would have returned: ${originalReturn}`);
                
                // Let's always add 5 to the result.
                returnValue.value = originalReturn + 5;
                console.log(`Modified return value to: ${returnValue.value}`);
            }
        });

        // Test the interception
        let result = maxMethod.invoke<number>(5, 10); // Normally 10
        // onEnter changes parameters[0] to 100. So effectively Max(100, 10) which is 100.
        // onLeave adds 5 to the result. So, 100 + 5 = 105.
        console.log(`maxMethod.invoke(5, 10) with interception returned: ${result}`);
        assert(result === 105, "Interception logic failed!");

        // Detach the interceptor
        console.log("Detaching interceptor...");
        listener.detach();

        result = maxMethod.invoke<number>(5, 10); // Should now be 10
        console.log(`maxMethod.invoke(5, 10) after detach returned: ${result}`);
        assert(result === 10, "Detach failed or original method not restored properly!");

        console.log("Method interception demonstration complete.");
    });
}

interceptMethod().catch(error => console.error(error.stack));
```

##### Advanced Tracing & Debugging
Beyond the simple `.trace()` on classes and methods, `Il2Cpp.Tracer` provides fine-grained control. `Il2Cpp.backtrace()` offers insights into call stacks.
```typescript
// (import "frida-il2cpp-bridge";)
async function advancedTracing() {
    await Il2Cpp.perform(async () => {
        const Corlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const SystemString = Corlib.classes["System.String"];

        // Example 1: Trace specific methods using Il2Cpp.Tracer
        console.log("Starting advanced trace for String.Concat and String.Substring...");
        Il2Cpp.trace() // Equivalent to new Il2Cpp.Tracer(applier)
            .methods(SystemString.methods.Concat, SystemString.methods.Substring) // Target specific methods
            .filterMethods(m => m.parameterCount == 2) // Further filter (e.g. only overloads with 2 params)
            .verbose(true) // Show all calls, even duplicates
            // .thread(Il2Cpp.mainThread) // Optionally filter by thread
            .attach(); // Start tracing

        // Il2Cpp.String.from("a").concat("b"); // Trigger trace

        // Example 2: Use backtracing on a method
        // const someMethod = SystemString.methods.ToLower;
        // if (someMethod) {
        //     console.log(`Attaching backtracer to ${someMethod.fullName}`);
        //     Il2Cpp.backtrace().methods(someMethod).attach();
        // }
        // To stop tracing: Interceptor.detachAll();
    });
}
// advancedTracing().catch(console.error);
```

##### Working with Delegates
You can create Il2Cpp delegates from JavaScript functions. This is useful for event handling or replacing delegate fields.
```typescript
// (import "frida-il2cpp-bridge";)
// Assume SomeClass has an event: public static event System.Action<string> OnSomethingHappened;
// Or a field: public System.Func<int, int> MyDelegateField;

async function workingWithDelegates() {
    await Il2Cpp.perform(async () => {
        const SystemActionString = Il2Cpp.Domain.reference.assemblies.mscorlib.image.class("System.Action`1").inflate(Il2Cpp.String.class);
        // const SomeClass = Il2Cpp.Domain.assembly("Assembly-CSharp").image.class("SomeClass");

        // Example: Create a delegate for an Action<string>
        const myAction = Il2Cpp.delegate(SystemActionString, (message: Il2Cpp.String) => {
            console.log(`Delegate called with: ${message.content}`);
        });
        console.log(`Created delegate: ${myAction.handle}`);

        // Now 'myAction' could be assigned to an event or field of the correct delegate type.
        // E.g., if SomeClass.OnSomethingHappened was a static field for the event's backing delegate:
        // SomeClass.fields.OnSomethingHappened.value = myAction;
        // Or if it's an instance field:
        // const instance = SomeClass.new();
        // instance.fields.MyDelegateField.value = myAction;
    });
}
// workingWithDelegates().catch(console.error);
```

##### Handling ref and out parameters
Methods with `ref` or `out` parameters require `Il2Cpp.Reference` objects to be passed for those arguments.
```typescript
// (import "frida-il2cpp-bridge";)
// Assume a class TestClass with method: public static bool TryParseInt(string s, out int result)
async function handleRefOutParams() {
    await Il2Cpp.perform(async () => {
        // const TestClass = Il2Cpp.Domain.assembly("Assembly-CSharp").image.class("TestClass");
        // const tryParseIntMethod = TestClass.tryMethod("TryParseInt", 2); // Name, paramCount

        // if (tryParseIntMethod) {
        //     const inputString = Il2Cpp.String.from("123");
        //     // For 'out int result', result is initially undefined but its type is Int32.
        //     const resultRef = Il2Cpp.reference(0, Il2Cpp.Int32.type); // Pass initial value (often ignored for out) and type

        //     const success = tryParseIntMethod.invoke<boolean>(inputString, resultRef);

        //     if (success) {
        //         console.log(`Parsed value: ${resultRef.value}`); // Access the value via .value
        //     } else {
        //         console.log("Parse failed.");
        //     }
        // }
    });
}
// handleRefOutParams().catch(console.error);
```

##### Pinning Objects with GCHandle
To prevent the Garbage Collector from moving an object, you can create a pinned `Il2Cpp.GCHandle`.
```typescript
// (import "frida-il2cpp-bridge";)
async function pinningObjects() {
    await Il2Cpp.perform(async () => {
        const myString = Il2Cpp.String.from("Persistent String");
        
        // Create a pinned handle
        const handle = myString.object.ref(true); // true for pinned
        console.log(`Object ${myString.handle} pinned with GCHandle: ${handle.handle}`);
        
        // The object myString.object is now pinned in memory.
        // Access the target object via handle.target
        console.log(`GCHandle target content: ${handle.target?.toString()}`);

        // Important: Free the handle when done to allow GC to collect the object
        handle.free();
        console.log("GCHandle freed.");
    });
}
// pinningObjects().catch(console.error);
```

### API
This section provides a reference for the core `Il2Cpp` types exposed by the bridge.

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
Represents an Il2Cpp array. You can create new arrays or get existing ones from fields or method calls.

**Note:** It's not possible to dynamically add or remove elements from an existing Il2Cpp array using this bridge (e.g., like JavaScript's `push` or `pop`). You can, however, create new arrays with different sizes or modify elements at existing indices.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function manipulateArray() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const SystemString = mscorlib.classes["System.String"]; // Class for System.String
        const SystemInt32 = mscorlib.classes["System.Int32"];   // Class for System.Int32

        if (!SystemString || !SystemInt32) {
            console.error("Required classes (System.String or System.Int32) not found.");
            return;
        }

        // Create a new Il2Cpp.Array of System.String
        console.log("Creating a new string array...");
        const stringArray = Il2Cpp.Array.from<Il2Cpp.String>(SystemString, [
            Il2Cpp.String.from("One"), // Create Il2Cpp.String instances for each element
            Il2Cpp.String.from("Two"),
            Il2Cpp.String.from("Three")
        ]);

        // Check array properties
        assert(stringArray.length === 3, "Array length should be 3");
        assert(stringArray.object.class.type.name === "System.String[]", "Array type name is incorrect");
        assert(stringArray.elementType.name === "System.String", "Element type name is incorrect");
        // For reference types like string, elementSize is the pointer size.
        // For value types, it's the size of the value type.
        assert(stringArray.elementSize === Process.pointerSize, "Element size for string array should be pointer size");

        // Iterate over the array (converts to a JS array of Il2Cpp.String objects)
        const jsArrayRepresentation = Array.from(stringArray);
        assert(jsArrayRepresentation.map(s => s.content).join(",") === "One,Two,Three", "Array content mismatch");

        // Get an element at a specific index
        const firstElement = stringArray.get(0);
        assert(firstElement.content === "One", "First element content is incorrect");

        // Set an element at a specific index
        console.log(`Original first element: "${stringArray.get(0).content}"`);
        stringArray.set(0, Il2Cpp.String.from("Replaced"));
        assert(stringArray.get(0).content === "Replaced", "Set operation failed");
        console.log(`Modified first element: "${stringArray.get(0).content}"`);

        // Example with a value type array (e.g., int[])
        console.log("Creating a new int array...");
        const intArray = Il2Cpp.Array.from<number>(SystemInt32, [10, 20, 30]);
        assert(intArray.length === 3, "Int array length should be 3");
        assert(intArray.elementType.name === "System.Int32", "Int array element type name is incorrect");
        assert(intArray.elementSize === 4, "Element size for int array should be 4"); // Typically System.Int32 is 4 bytes
        assert(intArray.get(1) === 20, "Int array get operation failed");
        intArray.set(1, 25);
        assert(intArray.get(1) === 25, "Int array set operation failed");
        console.log(`Int array elements: ${Array.from(intArray).join(", ")}`);
    });
}

manipulateArray().catch(error => console.error(error.stack));
```

##### `Il2Cpp.Assembly`
Represents a loaded Il2Cpp assembly (e.g., `Assembly-CSharp.dll`, `mscorlib.dll`). Assemblies contain compiled code and metadata, including classes and their definitions.

You typically access assemblies through `Il2Cpp.Domain.reference.assemblies`.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectAssembly() {
    await Il2Cpp.perform(async () => {
        // Get the Il2Cpp domain (root of the application's managed code)
        const domain = Il2Cpp.Domain.reference;

        // Assemblies are available as a map-like proxy by name
        const mscorlibAssembly = domain.assemblies["mscorlib"]; 
        const assemblyCSharp = domain.assemblies["Assembly-CSharp"]; // Common assembly for game scripts

        if (mscorlibAssembly) {
            console.log(`Found assembly: ${mscorlibAssembly.name}`);
            // Each assembly has an associated image, which contains the actual classes, methods, etc.
            const mscorlibImage = mscorlibAssembly.image;
            assert(mscorlibImage.name === "mscorlib.dll", "mscorlib image name mismatch"); // Image name often includes .dll
            assert(mscorlibAssembly.name === "mscorlib", "mscorlib assembly name mismatch"); // Assembly name usually doesn't
            console.log(`Image for mscorlib: ${mscorlibImage.name}`);
            
            // You can list classes in the assembly's image
            // const firstFewClasses = mscorlibImage.classes.slice(0, 5).map(c => c.fullName).join(", ");
            // console.log(`Some classes in mscorlib: ${firstFewClasses}...`);
        } else {
            console.log("mscorlib assembly not found.");
        }

        if (assemblyCSharp) {
            console.log(`Found assembly: ${assemblyCSharp.name}`);
            const csharpImage = assemblyCSharp.image;
            console.log(`Image for Assembly-CSharp: ${csharpImage.name}`);
            assert(csharpImage.name === "Assembly-CSharp.dll", "Assembly-CSharp image name mismatch");
            assert(assemblyCSharp.name === "Assembly-CSharp", "Assembly-CSharp assembly name mismatch");
        } else {
            console.log("Assembly-CSharp assembly not found. This is common if the game has no user scripts or they are in a different assembly.");
        }
        
        // You can also iterate through all assemblies
        console.log("\nListing all loaded assemblies:");
        for (const assembly of domain.assemblies) {
            console.log(`- ${assembly.name} (Image: ${assembly.image.name})`);
        }
    });
}

inspectAssembly().catch(error => console.error(error.stack));
```

##### `Il2Cpp.Class`
Represents an Il2Cpp class definition. It provides access to metadata about the class, such as its fields, methods, parent class, interfaces, and more. You typically get `Il2Cpp.Class` instances from an `Il2Cpp.Image`.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectClass() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

        // Get various class references
        const BooleanClass = mscorlib.classes["System.Boolean"];
        const Int32Class = mscorlib.classes["System.Int32"];
        const ObjectClass = mscorlib.classes["System.Object"];
        const DayOfWeekClass = mscorlib.classes["System.DayOfWeek"]; // An enum
        const MathClass = mscorlib.classes["System.Math"];
        const IFormattableClass = mscorlib.classes["System.IFormattable"]; // An interface
        const ListClass = mscorlib.tryClass("System.Collections.Generic.List`1"); // A generic class

        assert(BooleanClass, "System.Boolean class not found");
        assert(Int32Class, "System.Int32 class not found");
        // ... and so on for other classes

        // Name and Type
        console.log(`Class Name: ${BooleanClass.name}`); // Boolean
        console.log(`Class Namespace: ${BooleanClass.namespace}`); // System
        console.log(`Class FullName: ${BooleanClass.fullName}`); // System.Boolean
        assert(BooleanClass.type.name === "System.Boolean", "Type name mismatch");

        // Assembly and Image
        assert(BooleanClass.image.name === "mscorlib.dll", "Image name mismatch");
        assert(BooleanClass.assemblyName === "mscorlib", "Assembly name mismatch");
        
        // Hierarchy
        assert(BooleanClass.parent?.type.name === "System.ValueType", "Boolean parent should be ValueType");
        assert(ObjectClass.parent === null, "System.Object should have no parent");
        // Example: Check if List<T> implements IEnumerable<T> (simplified check)
        // const IEnumerableGenericName = "System.Collections.Generic.IEnumerable`1";
        // if (ListClass) {
        //     const hasIEnumerable = ListClass.interfaces.some(i => i.fullName.startsWith(IEnumerableGenericName.slice(0, -2)));
        //     console.log(`List\`1 implements a generic IEnumerable: ${hasIEnumerable}`);
        // }


        // Kind of Type (Enum, Interface, ValueType)
        console.log(`${DayOfWeekClass.fullName} is an enum: ${DayOfWeekClass.isEnum}`);
        assert(DayOfWeekClass.isEnum, "DayOfWeek should be an enum");
        assert(!ObjectClass.isEnum, "Object should not be an enum");

        console.log(`${IFormattableClass.fullName} is an interface: ${IFormattableClass.isInterface}`);
        assert(IFormattableClass.isInterface, "IFormattable should be an interface");
        assert(!ObjectClass.isInterface, "Object should not be an interface");

        console.log(`${Int32Class.fullName} is a value type: ${Int32Class.isValueType}`);
        assert(Int32Class.isValueType, "Int32 should be a value type");
        assert(!ObjectClass.isValueType, "Object should not be a value type (it's a reference type)");
        console.log(`${Int32Class.fullName} is a struct: ${Int32Class.isStruct}`); // isStruct = isValueType && !isEnum

        // Array Properties
        const booleanArrayClass = BooleanClass.arrayClass;
        console.log(`Array class for Boolean: ${booleanArrayClass.name}`); // Boolean[]
        assert(booleanArrayClass.name === "Boolean[]", "Boolean array class name");
        assert(booleanArrayClass.elementClass?.equals(BooleanClass), "Element class of Boolean[] should be Boolean");
        assert(Int32Class.arrayElementSize === 4, "Int32 element size in an array is 4 bytes");
        assert(ObjectClass.arrayElementSize === Process.pointerSize, "Object element size in an array is pointer size");

        // Static Constructor (.cctor)
        // MathClass likely has a static constructor. Let's initialize it if not already.
        if (MathClass.hasStaticConstructor) {
            console.log(`${MathClass.name} has a static constructor. Initializing...`);
            MathClass.initialize(); // Ensures .cctor is called
            // There isn't a direct 'isStaticConstructorFinished' property.
            // Calling .initialize() is the way to ensure it has run.
        }
        
        // Fields and Methods
        const piField = MathClass.tryField("PI");
        assert(piField, "PI field in System.Math not found");
        console.log(`Field PI in ${MathClass.name}: static=${piField!.isStatic}, type=${piField!.type.name}`);
        assert(piField!.isStatic, "Math.PI should be static");

        const absMethod = MathClass.tryMethod("Abs", 1); // Assuming Abs(int) or Abs(double) etc.
        assert(absMethod, "Abs method in System.Math not found");
        console.log(`Method Abs in ${MathClass.name}: static=${absMethod!.isStatic}, params=${absMethod!.parameterCount}`);
        assert(absMethod!.isStatic, "Math.Abs should be static");

        // Declaring class (for nested classes)
        const nestedClassExample = mscorlib.tryClass("System.Environment/SpecialFolder");
        if (nestedClassExample) {
            assert(nestedClassExample.declaringClass?.fullName === "System.Environment", "Declaring class for SpecialFolder");
            console.log(`${nestedClassExample.fullName} is nested within ${nestedClassExample.declaringClass!.fullName}`);
        }
        
        // Generics
        if (ListClass) {
            console.log(`${ListClass.name} is generic: ${ListClass.isGeneric}`); // True for List`1
            // To get a concrete generic type, e.g. List<string>:
            // const listOfString = ListClass.inflate(SystemString);
            // console.log(`Inflated List<string>: ${listOfString.fullName}`);
            // assert(listOfString.isInflated, "List<string> should be inflated");
            // assert(listOfString.generics[0].equals(SystemString), "Generic argument of List<string> should be System.String");
        }
        
        // Allocating and creating new objects (simple constructor)
        // const myObject = ObjectClass.new(); // Calls default constructor
        // console.log(`Allocated a new System.Object: ${myObject.handle}`);
        // assert(!myObject.handle.isNull(), "New object handle should not be null");

        console.log("Class inspection tests passed.");
    });
}

inspectClass().catch(error => console.error(error.stack));
```

#### `Il2Cpp.Domain`
Represents an Il2Cpp application domain. In Il2Cpp, there's typically only one main domain, often called the "IL2CPP Root Domain". The domain is the primary container for all loaded assemblies.

You usually start by getting a reference to the current domain.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectDomain() {
    await Il2Cpp.perform(async () => {
        // Get a reference to the root application domain
        const domain = Il2Cpp.Domain.reference;

        // Check its name (usually "IL2CPP Root Domain")
        console.log(`Current Domain Name: ${domain.name}`);
        assert(domain.name === "IL2CPP Root Domain", "Domain name mismatch");

        // The most common use of the domain is to access its assemblies
        console.log("\nAssemblies in this domain:");
        let assemblyCount = 0;
        for (const assembly of domain.assemblies) {
            console.log(`- ${assembly.name}`);
            assemblyCount++;
        }
        assert(assemblyCount > 0, "Should find at least mscorlib assembly");

        // You can also open (load) new assemblies into the domain if needed,
        // though this is a less common use case for runtime manipulation.
        // const newAssembly = domain.open("path/to/some.dll"); // Example, requires valid path
    });
}

inspectDomain().catch(error => console.error(error.stack));
```

#### `Il2Cpp.Field`
Represents a field within a class. Fields can be static (belonging to the class itself) or instance (belonging to an object of the class). They also have types and can have attributes like `literal` (for compile-time constants) or `threadStatic`. You obtain `Il2Cpp.Field` instances from an `Il2Cpp.Class` by accessing its `fields` property (which might be an array or a map-like object) or using helper methods like `tryField()`.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectAndManipulateFields() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

        // --- Static Fields ---
        const MathClass = mscorlib.classes["System.Math"];
        const PIField = MathClass.tryField("PI"); // public static readonly double PI = 3.141592653589793;

        assert(PIField, "System.Math.PI field not found");
        console.log(`Field: ${PIField!.name}`);
        console.log(`  - Belongs to Class: ${PIField!.class.fullName}`); // System.Math
        console.log(`  - Type: ${PIField!.type.name}`); // System.Double
        console.log(`  - Is Static: ${PIField!.isStatic}`); // true
        console.log(`  - Is Literal (const): ${PIField!.isLiteral}`); // true, as it's a compile-time constant
        console.log(`  - Is ThreadStatic: ${PIField!.isThreadStatic}`); // false
        
        // Get static field value
        const piValue = PIField!.value; // Type will be number (for double)
        console.log(`  - Value: ${piValue}`);
        assert(typeof piValue === "number" && piValue > 3.14 && piValue < 3.15, "PI value is incorrect");

        // Setting a literal/readonly static field will typically not work or throw an error.
        // PIField.value = 3.0; // This would likely fail or have no effect.

        const DateTimeClass = mscorlib.classes["System.DateTime"];
        const MinValueField = DateTimeClass.tryField("MinValue"); // public static readonly DateTime MinValue;
        assert(MinValueField, "System.DateTime.MinValue field not found");
        console.log(`Static field ${MinValueField!.name} in ${DateTimeClass.name} has type ${MinValueField!.type.name}`);
        const minValueObj = MinValueField!.value as Il2Cpp.Object; // DateTime is a struct, so it's a ValueType (boxed as Object here)
        console.log(`  - MinValue (as Object): ${minValueObj.toString()}`); // Might print "01/01/0001 00:00:00" or similar
        
        // --- Instance Fields ---
        // Let's use System.Guid, which has private instance fields _a, _b, ... _k
        const GuidClass = mscorlib.classes["System.Guid"];
        assert(GuidClass, "System.Guid class not found");

        // Create a new Guid object to inspect its instance fields
        // Guid has a constructor that takes a string, e.g., Guid(string)
        // For simplicity, let's try to get Guid.Empty's fields or create one with new Guid()
        
        let guidObject: Il2Cpp.Object;
        const emptyGuidStaticField = GuidClass.tryField("Empty");
        if (emptyGuidStaticField) {
            guidObject = emptyGuidStaticField.value as Il2Cpp.Object;
            console.log("Using Guid.Empty for instance field example.");
        } else {
            // If Guid.Empty static field isn't found (e.g. older .NET), create new Guid.
            // This requires finding a constructor. Guid has a default .ctor().
            // guidObject = GuidClass.new(); // Simpler if new() is robust for all types
            // For now, let's assume Guid.Empty is available or skip if not.
            console.warn("Guid.Empty static field not found, instance field example might be limited.");
            return; 
        }
        
        // Example: Get the private instance field "_a" from a Guid object
        const fieldA = GuidClass.tryField("_a"); // private int _a;
        if (fieldA && guidObject) {
            console.log(`Instance field: ${fieldA.name} in ${GuidClass.name}`);
            console.log(`  - Is Static: ${fieldA.isStatic}`); // false
            
            // Get instance field value. Requires an instance of the object.
            const valueOfA_onGuidEmpty = fieldA.with(guidObject).value;
            console.log(`  - Value of _a on Guid.Empty: ${valueOfA_onGuidEmpty}`); // Should be 0 for Guid.Empty
            assert(valueOfA_onGuidEmpty === 0, "_a on Guid.Empty should be 0");

            // Set instance field value (if not readonly and accessible)
            // fieldA.with(guidObject).value = 123; // This would modify the _a field of guidObject
            // const newValueOfA = fieldA.with(guidObject).value;
            // console.log(`  - New value of _a: ${newValueOfA}`);
            // assert(newValueOfA === 123, "Setting instance field _a failed");
            // Note: Modifying private fields of system types like Guid might have unintended consequences.
        } else {
            console.log("Field _a not found in System.Guid or guidObject not available.");
        }
        console.log("Field inspection demo complete.");
    });
}

inspectAndManipulateFields().catch(error => console.error(error.stack));
```

#### `Il2Cpp.Image`
Represents an Il2Cpp image, which is essentially a managed assembly file (like a .dll or .so) loaded into memory. An image contains the metadata and definitions for classes, methods, and other types.

You primarily get `Il2Cpp.Image` instances from an `Il2Cpp.Assembly`.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectImage() {
    await Il2Cpp.perform(async () => {
        const domain = Il2Cpp.Domain.reference;
        const mscorlibAssembly = domain.assemblies["mscorlib"];
        
        assert(mscorlibAssembly, "mscorlib assembly not found");
        const mscorlibImage = mscorlibAssembly.image;

        // Name of the image (often includes the file extension)
        console.log(`Image Name: ${mscorlibImage.name}`); // e.g., "mscorlib.dll"
        assert(mscorlibImage.name === "mscorlib.dll", "Image name should be mscorlib.dll");

        // Get the assembly this image belongs to
        assert(mscorlibImage.assembly.equals(mscorlibAssembly), "Image's assembly should match the source assembly");

        // Access classes within the image
        console.log(`\nLooking for classes in ${mscorlibImage.name}:`);
        const objectClass = mscorlibImage.classes["System.Object"];
        const stringClass = mscorlibImage.tryClass("System.String"); // tryClass returns null if not found

        assert(objectClass, "System.Object class not found in mscorlib image");
        assert(stringClass, "System.String class not found in mscorlib image");

        console.log(`- Found class: ${objectClass.fullName}`);
        console.log(`- Found class: ${stringClass!.fullName}`); // Safe due to assert above

        // You can iterate through all classes in an image
        // console.log("\nFirst few classes in mscorlib.dll:");
        // mscorlibImage.classes.slice(0, 5).forEach(klass => {
        //     console.log(`  - ${klass.fullName}`);
        // });
        
        // An image also has a list of all exported types (usually same as classes for Il2Cpp)
        // const exportedTypeCount = mscorlibImage.exportedTypes.length;
        // const classCount = mscorlibImage.classes.length;
        // console.log(`Number of classes: ${classCount}, Number of exported types: ${exportedTypeCount}`);

        console.log("Image inspection demo complete.");
    });
}

inspectImage().catch(error => console.error(error.stack));
```

#### `Il2Cpp.Method`
Represents an Il2Cpp method definition. It provides access to metadata like the method's name, containing class, parameters, return type, and whether it's static or generic. You can also use it to invoke the method, replace its implementation, or intercept its calls. You obtain `Il2Cpp.Method` instances from an `Il2Cpp.Class` by accessing its `methods` property (which might be an array or a map-like object keyed by name/signature) or using helper methods like `tryMethod()`.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectAndUseMethods() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

        const BooleanClass = mscorlib.classes["System.Boolean"];
        const MathClass = mscorlib.classes["System.Math"];
        const StringClass = mscorlib.classes["System.String"];

        assert(BooleanClass && MathClass && StringClass, "Required classes not found");

        // Get some method references
        const toStringMethod = BooleanClass.methods.ToString; // Instance method
        const parseMethod = BooleanClass.tryMethod("Parse", 1); // Static method: Boolean.Parse(string)
        const maxMethod = MathClass.tryMethod("Max", 2);    // Static method: Math.Max(int, int)
        const substringMethod = StringClass.tryMethod("Substring", 2); // Instance method: string.Substring(int, int)

        assert(toStringMethod && parseMethod && maxMethod && substringMethod, "Required methods not found");

        // Method properties
        console.log(`Method: ${toStringMethod.name} in ${toStringMethod.class.fullName}`);
        assert(toStringMethod.class.equals(BooleanClass), "Method's class mismatch");
        assert(toStringMethod.name === "ToString", "Method name mismatch");
        console.log(`  - Is Static: ${toStringMethod.isStatic}`); // false
        assert(!toStringMethod.isStatic, "ToString should be an instance method");
        console.log(`  - Is Generic: ${toStringMethod.isGeneric}`); // false
        console.log(`  - Parameter Count: ${toStringMethod.parameterCount}`); // 0 for this ToString
        console.log(`  - Return Type: ${toStringMethod.returnType.name}`); // System.String
        console.log(`  - Virtual Address: ${toStringMethod.virtualAddress}`); // NativePointer to the method's implementation

        assert(parseMethod.isStatic, "Boolean.Parse should be static");
        assert(parseMethod.parameterCount === 1, "Boolean.Parse parameter count mismatch");
        
        // Parameters
        const parseParameters = parseMethod.parameters;
        assert(parseParameters.length === 1, "Parse method should have 1 parameter");
        console.log(`  - Parameter 0: Name='${parseParameters[0].name}', Type='${parseParameters[0].type.name}'`); // Name might be 'value'

        // Invoking methods
        // 1. Invoke a static method
        const trueString = Il2Cpp.String.from("true");
        const parsedTrue = parseMethod.invoke<boolean>(trueString); // Generic type arg is the expected return type
        console.log(`Boolean.Parse("true") returned: ${parsedTrue}`);
        assert(parsedTrue === true, "Parse('true') failed");

        // 2. Invoke an instance method
        const myString = Il2Cpp.String.from("HelloFrida");
        // For instance methods, the first argument to invoke() is the instance itself.
        const sub = substringMethod.invoke<Il2Cpp.String>(myString, 5, 5); // "HelloFrida".Substring(5, 5)
        console.log(`"${myString.content}".Substring(5, 5) returned: "${sub.content}"`);
        assert(sub.content === "Frida", "Substring failed");

        // Method Implementation Replacement (already covered in snippets, brief example)
        const originalMaxImpl = maxMethod.implementation;
        maxMethod.implementation = (_instance, params) => {
            return Math.min(params[0].value as number, params[1].value as number); // Make Max return Min
        };
        assert(maxMethod.invoke<number>(10, 20) === 10, "Max replacement (as Min) failed");
        maxMethod.implementation = originalMaxImpl; // Revert
        assert(maxMethod.invoke<number>(10, 20) === 20, "Max revert failed");

        // Method Interception (already covered in snippets, brief example)
        const interceptor = maxMethod.intercept({
            onEnter: (_instance, params) => { params[0].value = 0; }, // Always make first arg 0
            onLeave: (ret) => { ret.value = (ret.value as number) + 1; } // Add 1 to result
        });
        // Max(0, 20) = 20. 20 + 1 = 21.
        assert(maxMethod.invoke<number>(10, 20) === 21, "Max interception failed");
        interceptor.detach();
        assert(maxMethod.invoke<number>(10, 20) === 20, "Max interceptor detach failed");

        console.log("Method inspection and usage demo complete.");
    });
}

inspectAndUseMethods().catch(error => console.error(error.stack));
```

#### `Il2Cpp.Object`
Represents an instance of an Il2Cpp class (an object). This is the base type for all managed objects in Il2Cpp. For value types (structs), they are represented as `Il2Cpp.ValueType` when unboxed, but they become `Il2Cpp.Object` when boxed (e.g., when stored in a collection or passed to a method expecting `System.Object`).

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectAndUseObjects() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const ObjectClass = mscorlib.classes["System.Object"];
        const StringClass = mscorlib.classes["System.String"];
        const DateTimeClass = mscorlib.classes["System.DateTime"]; // DateTime is a ValueType (struct)

        assert(ObjectClass && StringClass && DateTimeClass, "Required classes not found");

        // Creating a new object (reference type)
        // ObjectClass.new() calls the default constructor of System.Object
        const myObject = ObjectClass.new(); 
        console.log(`Created a new System.Object at handle: ${myObject.handle}`);
        assert(!myObject.handle.isNull(), "Object handle should not be null");

        // Get the class of an object
        assert(myObject.class.equals(ObjectClass), "myObject should be of class System.Object");

        // Get the base class of an object instance (if any)
        // For myObject (System.Object), base will be null.
        // Let's create a String object.
        const myString = Il2Cpp.String.from("test_string_obj"); // This is an Il2Cpp.String, which is an Il2Cpp.Object
        console.log(`Created a System.String object: "${myString.content}"`);
        assert(myString.class.equals(StringClass), "myString should be of class System.String");
        // The 'base' property on an Il2Cpp.Object gives an Il2Cpp.Object instance of its base type's fields.
        // To get the base class definition, use myString.class.parent
        assert(myString.class.parent?.equals(ObjectClass), "String's parent class should be Object");


        // Calling an instance method
        const lengthMethod = StringClass.tryMethod("get_Length"); // string.Length property getter
        assert(lengthMethod, "String.get_Length method not found");
        const length = lengthMethod.invoke<number>(myString); // Call on myString instance
        console.log(`Length of "${myString.content}" is ${length}`);
        assert(length === myString.content?.length, "String length mismatch");
        
        // Accessing an instance field (if available and accessible)
        // System.String has a private field like '_stringLength' or similar, but it's not directly public.
        // For an example, if 'myObject' had a public instance field 'myField', you'd do:
        // const myFieldDesc = myObject.class.fields.myField;
        // const fieldValue = myFieldDesc.with(myObject).value;

        // Boxing and Unboxing (for ValueTypes)
        // Create a DateTime object (ValueType). DateTimeClass.new() creates a boxed DateTime.
        const dateTimeObject = DateTimeClass.new(); // Calls default constructor, creates a boxed DateTime
        console.log(`Created a boxed DateTime object: ${dateTimeObject.toString()}`);
        assert(dateTimeObject.class.equals(DateTimeClass), "dateTimeObject should be of class DateTime");

        // Unbox it to work with it as a ValueType
        const dateTimeValueType = dateTimeObject.unbox();
        console.log(`Unboxed DateTime: Handle ${dateTimeValueType.handle}, Class ${dateTimeValueType.class.name}`);
        // You can access fields directly on the ValueType instance
        // e.g., if DateTime had a public field 'year': dateTimeValueType.fields.year.value
        // For DateTime, fields are often private, use methods like get_Year()
        const yearMethod = DateTimeClass.tryMethod("get_Year");
        assert(yearMethod, "DateTime.get_Year not found");
        // To call a method on a ValueType, you typically need its boxed version if the method expects 'this'
        // or if the method is non-static.
        // However, some methods on ValueType might be accessible directly if the bridge handles it.
        // For robust calls, use the boxed object:
        const year = yearMethod.invoke<number>(dateTimeObject); // Call on the boxed object
        console.log(`Year of dateTimeObject: ${year}`); 
        // Default DateTime constructor initializes to 01/01/0001, so year should be 1.
        assert(year === 1, "Default DateTime year should be 1");


        // Box a ValueType back into an Object
        const reBoxedDateTime = dateTimeValueType.box();
        console.log(`Re-boxed DateTime object: ${reBoxedDateTime.toString()}`);
        assert(reBoxedDateTime.class.equals(DateTimeClass), "Re-boxed DateTime should be of class DateTime");
        // Note: reBoxedDateTime and dateTimeObject are different boxed instances,
        // so their handles will likely be different, even if they represent the same value.
        assert(!reBoxedDateTime.handle.equals(dateTimeObject.handle), "Boxing usually creates a new wrapper object");

        console.log("Object inspection and usage demo complete.");
    });
}

inspectAndUseObjects().catch(error => console.error(error.stack));
```

#### `Il2Cpp.Parameter`
Represents a parameter of a method. It provides information such as the parameter's name, its position (index) in the method signature, and its type.

You typically access `Il2Cpp.Parameter` instances through the `parameters` array of an `Il2Cpp.Method`.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectParameters() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const MathClass = mscorlib.classes["System.Math"];
        assert(MathClass, "System.Math class not found");

        // Get the Math.Max(int val1, int val2) method
        const maxMethod = MathClass.tryMethod("Max", 2);
        assert(maxMethod, "Math.Max(int, int) method not found");

        console.log(`Inspecting parameters for: ${maxMethod.class.name}.${maxMethod.name}`);
        
        const parameters = maxMethod.parameters;
        assert(parameters.length === 2, "Math.Max should have 2 parameters");

        // First parameter (val1)
        const val1Param = parameters[0];
        console.log(`Parameter 0:`);
        console.log(`  - Name: ${val1Param.name}`); // Name might be "val1" or similar, depends on debug info
        console.log(`  - Position: ${val1Param.position}`); // 0
        console.log(`  - Type: ${val1Param.type.name}`); // System.Int32
        assert(val1Param.position === 0, "First parameter position should be 0");
        assert(val1Param.type.name === "System.Int32", "First parameter type should be System.Int32");

        // Second parameter (val2)
        const val2Param = parameters[1];
        console.log(`Parameter 1:`);
        console.log(`  - Name: ${val2Param.name}`); // Name might be "val2"
        console.log(`  - Position: ${val2Param.position}`); // 1
        console.log(`  - Type: ${val2Param.type.name}`); // System.Int32
        assert(val2Param.position === 1, "Second parameter position should be 1");
        assert(val2Param.type.name === "System.Int32", "Second parameter type should be System.Int32");
        
        // Example with a method that has different parameter types
        const StringClass = mscorlib.classes["System.String"];
        assert(StringClass, "System.String class not found");
        const substringMethod = StringClass.tryMethod("Substring", 2); // Substring(int startIndex, int length)
        assert(substringMethod, "String.Substring(int, int) not found");

        console.log(`\nInspecting parameters for: ${substringMethod.class.name}.${substringMethod.name}`);
        const substringParams = substringMethod.parameters;
        assert(substringParams.length === 2);

        console.log(`Parameter 0 ('this' is implicit): Name='${substringParams[0].name}', Type='${substringParams[0].type.name}', Position=${substringParams[0].position}`);
        assert(substringParams[0].type.name === "System.Int32"); // startIndex
        console.log(`Parameter 1: Name='${substringParams[1].name}', Type='${substringParams[1].type.name}', Position=${substringParams[1].position}`);
        assert(substringParams[1].type.name === "System.Int32"); // length

        console.log("Parameter inspection demo complete.");
    });
}

inspectParameters().catch(error => console.error(error.stack));
```

#### `Il2Cpp.String`
Represents an Il2Cpp string in the application's memory. This bridge type allows you to create new Il2Cpp strings from JavaScript strings or read the content of existing Il2Cpp strings.

Note: `Il2Cpp.String` is a wrapper around a handle to the native `System.String` object. Its `content` property allows getting/setting the string's value as a JavaScript string.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function manipulateIl2CppString() {
    await Il2Cpp.perform(async () => {
        // Create a new Il2Cpp.String in the target application's memory
        const greeting = Il2Cpp.String.from("Hello, Frida!");
        console.log(`Created Il2Cpp.String with content: "${greeting.content}"`);

        // Accessing content
        assert(greeting.content === "Hello, Frida!", "String content mismatch after creation");

        // Modifying content
        // This allocates a new Il2Cpp string internally and updates the handle if the length changes,
        // or modifies the content in-place if possible (usually for same or smaller length).
        console.log(`Original string length: ${greeting.length}`);
        greeting.content = "Hi!";
        console.log(`Changed content to: "${greeting.content}"`);
        assert(greeting.content === "Hi!", "String content mismatch after modification");
        console.log(`New string length: ${greeting.length}`);
        assert(greeting.length === 3, "String length should be 3 after modification");

        // Check properties
        assert(greeting.object.class.type.name === "System.String", "Object type name should be System.String");
        assert(greeting.object.class.type.typeEnum === Il2Cpp.Type.Enum.String, "Object type enum should be String");

        // Using an Il2Cpp.String when invoking a method that expects a System.String
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const StringClass = mscorlib.classes["System.String"];
        assert(StringClass, "System.String class not found");

        const concatMethod = StringClass.tryMethod("Concat", 2); // String.Concat(string, string)
        assert(concatMethod, "String.Concat(string, string) method not found");

        const str1 = Il2Cpp.String.from("Frida ");
        const str2 = Il2Cpp.String.from("Rocks!");
        
        // Pass Il2Cpp.String instances directly
        const resultString = concatMethod.invoke<Il2Cpp.String>(str1, str2); 
        console.log(`String.Concat("${str1.content}", "${str2.content}") result: "${resultString.content}"`);
        assert(resultString.content === "Frida Rocks!", "String.Concat failed");

        console.log("Il2Cpp.String manipulation demo complete.");
    });
}

manipulateIl2CppString().catch(error => console.error(error.stack));
```

#### `Il2Cpp.Type`
Represents an Il2Cpp type. While `Il2Cpp.Class` represents the definition of a class, `Il2Cpp.Type` provides more specific information about how that class (or struct, primitive, array, pointer, etc.) is represented in terms of its type information within the Il2Cpp runtime.

Every `Il2Cpp.Class` has a corresponding `Il2Cpp.Type` accessible via its `.type` property.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectIl2CppTypes() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;

        const Int32Class = mscorlib.classes["System.Int32"];
        const StringClass = mscorlib.classes["System.String"];
        const ObjectClass = mscorlib.classes["System.Object"];
        const VoidClass = mscorlib.classes["System.Void"]; // Represents 'void' type

        assert(Int32Class && StringClass && ObjectClass && VoidClass, "Required classes not found");

        const int32Type = Int32Class.type;
        const stringType = StringClass.type;
        const objectType = ObjectClass.type;
        const voidType = VoidClass.type;

        // Name of the type (often same as class full name for simple types)
        console.log(`Type Name for System.Int32: ${int32Type.name}`); // System.Int32
        assert(int32Type.name === "System.Int32", "Int32 type name mismatch");

        // Get the Il2Cpp.Class from an Il2Cpp.Type
        assert(int32Type.class.equals(Int32Class), "Type's class should be the original class");

        // Type Enum (identifies the kind of type)
        console.log(`Type Enum for System.Int32: ${int32Type.typeEnum}`); // I4
        assert(int32Type.typeEnum === Il2Cpp.Type.Enum.I4, "Int32 type enum should be I4");
        assert(stringType.typeEnum === Il2Cpp.Type.Enum.String, "String type enum should be String");
        assert(objectType.typeEnum === Il2Cpp.Type.Enum.Object, "Object type enum should be Object");
        assert(voidType.typeEnum === Il2Cpp.Type.Enum.Void, "Void type enum should be Void");
        
        // For arrays, `dataType` gives the type of the elements
        const intArrayClass = Int32Class.arrayClass; // Get the class for Int32[]
        const intArrayType = intArrayClass.type;
        console.log(`Type Name for Int32[]: ${intArrayType.name}`); // System.Int32[]
        assert(intArrayType.typeEnum === Il2Cpp.Type.Enum.Array, "Int32[] type enum should be Array");
        // dataType points to the Il2Cpp.Type of the array elements
        assert(intArrayType.dataType?.equals(int32Type), "Data type of Int32[] should be Int32");
        console.log(`Element type of Int32[]: ${intArrayType.dataType?.name}`); // System.Int32

        // For pointers, `dataType` also gives the pointed-to type
        // Example: Get a pointer type (e.g., Int32*)
        // This is less direct to obtain without specific method signatures returning pointers,
        // but if you had an Il2Cpp.Type for "System.Int32*", its .dataType would be System.Int32.
        // const intPtrType = someMethod.parameters[0].type; // if param was int*
        // if (intPtrType.typeEnum === Il2Cpp.Type.Enum.Ptr) {
        //     console.log(`Pointer type ${intPtrType.name} points to ${intPtrType.dataType?.name}`);
        // }
        
        // The `attributes` property gives type flags (more advanced)
        // console.log(`Attributes for Int32 type: ${int32Type.attributes}`);

        // Check if a type is by reference (e.g., for 'out' or 'ref' parameters)
        // This is typically seen on Il2Cpp.Parameter.type, not directly on a class's type.
        // if (someParameter.type.isByReference) {
        //     console.log(`Parameter ${someParameter.name} is by reference.`);
        // }

        console.log("Il2Cpp.Type inspection demo complete.");
    });
}

inspectIl2CppTypes().catch(error => console.error(error.stack));
```

#### `Il2Cpp.ValueType`
Represents an instance of a value type (struct) in Il2Cpp. Unlike classes (reference types), value types are not objects on the heap by default; they are typically stored directly in variables or as part of other objects. When they are treated as objects (e.g., passed to a method expecting `System.Object`), they get "boxed" into an `Il2Cpp.Object`.

`Il2Cpp.ValueType` is a wrapper around the native memory of a struct. You can access its fields and box it to an `Il2Cpp.Object`.

```typescript
import "frida-il2cpp-bridge";
import assert from "assert"; // Assuming 'assert' is available

async function inspectValueType() {
    await Il2Cpp.perform(async () => {
        const mscorlib = Il2Cpp.Domain.reference.assemblies.mscorlib.image;
        const DateTimeClass = mscorlib.classes["System.DateTime"];
        assert(DateTimeClass, "System.DateTime class not found");

        // Create a new DateTime object (which is a struct, a value type).
        // DateTimeClass.new() returns a boxed DateTime (an Il2Cpp.Object).
        const dateTimeObject = DateTimeClass.new(); // e.g., 01/01/0001 00:00:00
        
        // To get an Il2Cpp.ValueType, we unbox the Il2Cpp.Object.
        const dateTimeValue = dateTimeObject.unbox();
        console.log(`Unboxed DateTime: Handle ${dateTimeValue.handle}, Class ${dateTimeValue.class.name}`);

        // Verify the class of the ValueType
        assert(dateTimeValue.class.equals(DateTimeClass), "ValueType's class should be DateTime");

        // Accessing fields of a ValueType:
        // Fields of DateTime (like 'ticks', 'dateData') are typically private.
        // Public data is usually accessed via methods/properties (e.g., get_Year, get_Month).
        // If DateTime had public fields 'year', 'month', 'day', you could access them like:
        // const year = dateTimeValue.fields.year.value;
        // const month = dateTimeValue.fields.month.value;
        // console.log(`Year from ValueType fields (if public): ${year}`);
        
        // Let's call methods to get year, month, day using the boxed object,
        // as methods are called on objects.
        const getYearMethod = DateTimeClass.tryMethod("get_Year");
        assert(getYearMethod, "DateTime.get_Year method not found");
        const year = getYearMethod.invoke<number>(dateTimeObject); // Call on the boxed object
        console.log(`Year from method call: ${year}`);
        assert(year === 1, "Default DateTime year should be 1");

        // Box the ValueType back to an Il2Cpp.Object
        const reBoxedObject = dateTimeValue.box();
        console.log(`Re-boxed DateTime object: Handle ${reBoxedObject.handle}, Class ${reBoxedObject.class.name}`);
        assert(reBoxedObject.class.equals(DateTimeClass), "Re-boxed object's class should be DateTime");
        // The reBoxedObject is a new boxed instance.
        assert(!reBoxedObject.handle.equals(dateTimeObject.handle), "Re-boxed object should have a new handle");

        // Example with a struct that has more accessible fields (hypothetical)
        // Let's imagine a struct `MyPoint { public int X; public int Y; }`
        // If MyPointClass was defined:
        // const myPointValue = MyPointClass.new().unbox(); // Get as ValueType
        // myPointValue.fields.X.value = 10;
        // myPointValue.fields.Y.value = 20;
        // assert(myPointValue.fields.X.value === 10);
        // const myPointBoxed = myPointValue.box();
        // Now myPointBoxed is an Il2Cpp.Object representing the MyPoint struct with X=10, Y=20.

        console.log("Il2Cpp.ValueType inspection demo complete.");
    });
}

inspectValueType().catch(error => console.error(error.stack));
```
