# frida-il2cpp-bridge

[![Frida](https://img.shields.io/badge/-frida-ef6456?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyAgIHZlcnNpb249IjEuMSIgICBpZD0iTGF5ZXJfMSIgICB4PSIwcHgiICAgeT0iMHB4IiAgIHZpZXdCb3g9IjAgMCA5LjcyOTk3OTkgMTAuOTM1NzEyIiAgIGVuYWJsZS1iYWNrZ3JvdW5kPSJuZXcgMCAwIDIwNC40IDM5IiAgIHhtbDpzcGFjZT0icHJlc2VydmUiICAgc29kaXBvZGk6ZG9jbmFtZT0ibG9nby5zdmciICAgd2lkdGg9IjkuNzI5OTc5NSIgICBoZWlnaHQ9IjEwLjkzNTcxMiIgICBpbmtzY2FwZTp2ZXJzaW9uPSIxLjEgKGNlNjY2M2IzYjcsIDIwMjEtMDUtMjUpIiAgIHhtbG5zOmlua3NjYXBlPSJodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy9uYW1lc3BhY2VzL2lua3NjYXBlIiAgIHhtbG5zOnNvZGlwb2RpPSJodHRwOi8vc29kaXBvZGkuc291cmNlZm9yZ2UubmV0L0RURC9zb2RpcG9kaS0wLmR0ZCIgICB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnMgICBpZD0iZGVmczkiIC8+PHNvZGlwb2RpOm5hbWVkdmlldyAgIGlkPSJuYW1lZHZpZXc3IiAgIHBhZ2Vjb2xvcj0iI2ZmZmZmZiIgICBib3JkZXJjb2xvcj0iIzY2NjY2NiIgICBib3JkZXJvcGFjaXR5PSIxLjAiICAgaW5rc2NhcGU6cGFnZXNoYWRvdz0iMiIgICBpbmtzY2FwZTpwYWdlb3BhY2l0eT0iMC4wIiAgIGlua3NjYXBlOnBhZ2VjaGVja2VyYm9hcmQ9IjAiICAgc2hvd2dyaWQ9ImZhbHNlIiAgIGZpdC1tYXJnaW4tdG9wPSIwIiAgIGZpdC1tYXJnaW4tbGVmdD0iMCIgICBmaXQtbWFyZ2luLXJpZ2h0PSIwIiAgIGZpdC1tYXJnaW4tYm90dG9tPSIwIiAgIGlua3NjYXBlOnpvb209IjYuOTE3ODA4NCIgICBpbmtzY2FwZTpjeD0iLTAuMTQ0NTU0NDUiICAgaW5rc2NhcGU6Y3k9Ii04LjYwMDk4OTkiICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxOTIwIiAgIGlua3NjYXBlOndpbmRvdy1oZWlnaHQ9IjEwMDgiICAgaW5rc2NhcGU6d2luZG93LXg9IjAiICAgaW5rc2NhcGU6d2luZG93LXk9IjAiICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSIgICBpbmtzY2FwZTpjdXJyZW50LWxheWVyPSJMYXllcl8xIiAvPjxnICAgaWQ9Imc0IiAgIHN0eWxlPSJkaXNwbGF5OmlubGluZTtmaWxsOiNmZmZmZmYiICAgdHJhbnNmb3JtPSJtYXRyaXgoMC4yODA0MDI4NiwwLDAsMC4yODA0MDI4NiwtMTEuNTgwNjM4LDApIj48cGF0aCAgIGZpbGw9IiNmZmZmZmYiICAgZD0iTSA1MS40LDM5IEggNDEuMyBMIDQ5LjcsMjYuMSBDIDQ0LjksMjMuOCA0Mi4zLDE5LjYgNDIuMywxMy41IDQyLjMsNC44IDQ4LjIsMCA1OC41LDAgSCA3NiBWIDM5IEggNjcgViAyOCBIIDU4LjUgNTcuNyBaIE0gNjcsMjAgViA3IGggLTguNSBjIC00LjksMCAtNy43LDIgLTcuNyw2LjQgMCw0LjUgMi44LDYuNiA3LjcsNi42IHoiICAgaWQ9InBhdGgyIiAgIHN0eWxlPSJmaWxsOiNmZmZmZmYiIC8+PC9nPjwvc3ZnPg==)](https://frida.re)
[![NPM](https://img.shields.io/npm/v/frida-il2cpp-bridge?label=&logo=npm&style=for-the-badge)](https://npmjs.org/package/frida-il2cpp-bridge)

A Frida module to dump, trace or hijack any Il2Cpp application at runtime, without needing the `global-metadata.dat` file.

![code](https://user-images.githubusercontent.com/46219656/153902126-062ee74c-df0b-49d0-8c0f-3a306bf1a52d.png)


## Features

- Dump classes, methods, fields and so on
- Trace, intercept and replace method calls
- Mess around with C# runtime
- Il2Cpp structs and global metadata free
- (TODO) Emit C scaffold code to improve static analysis

## Compatibility

#### Unity version
It should work for any Unity version in the range **5.3.0** - **2022.1.x**.

#### Platforms
**Android**, **Linux**, **Windows**, **iOS**, **macOS** are supported.
However, only Android and Linux are tested: expect breakage if you are using another platform.

## Changelog

### 0.7.13
- Add `Il2Cpp.Thread::schedule` to schedule a delayed callback:
  ```ts
  Il2Cpp.perform(() => {
    const Class: Il2Cpp.Class = ...;

    Class.method("MethodName").implementation = function () {
      // we probably are on the "main" thread now
      
      // non blocking
      Il2Cpp.currentThread?.schedule(() => {
        // we are on the same thread!
      }, 1000);

      return this..method("MethodName").invoke();
    };
  });
  ```
  Of course, it can be used to schedule a callback on a specific thread (see version `0.7.6` release notes). Sometimes, you could face an access violation/abort error when trying to invoke a Il2Cpp function within the wrong thread.
  ```ts
  Il2Cpp.perform(() => {
    const Method: Il2Cpp.Method = ...;

    // access violation :(
    Method.invoke();

    Il2Cpp.attachedThreads[0].schedule(() => {
      // works :)
      Method.invoke();
    });
  });
  ```
  **Note**: `Il2Cpp.Thread::schedule` similar to `Il2Cpp::scheduleOnInitializerThread`. However, they use different approaches. Eventually, one of them will be removed. \
  **Note**: `Il2Cpp.Thread::schedule` may not work with old Unity versions.

### 0.7.11
- Fix #171.

### 0.7.10
- Add `Il2Cpp.Reference::to` to easily create a `Il2Cpp.Reference`:
  ```ts
  Il2Cpp.perform(() => {
    const TryParse = Il2Cpp.Image.corlib.class("System.Boolean").method("TryParse");

    const value = Il2Cpp.Reference.to(false);

    console.log(value); // ->false
    TryParse.invoke(Il2Cpp.String.from("TrUe"), value);
    console.log(value); // ->true
  });
  ```
  A `Il2Cpp.Type` is required when creating a reference to a `number` or `NativePointer` in order to disambiguate their representation:
  ```ts
  const value = Il2Cpp.Reference.to(1355, Il2Cpp.Image.corlib.class("System.UInt16").type);
  ```
- Make `Il2Cpp.Object::unbox` directly return a `Il2Cpp.ValueType`:
  ```ts
  // old
  const valueType = new Il2Cpp.ValueType(object.unbox(), object.class.type);
  // new
  const valueType = object.unbox();
  ```

### 0.7.9
- Minor things.

### 0.7.8
- Add `Il2Cpp::installExceptionListener`.
- Fix #132.

### 0.7.7
- Fix #107.

### 0.7.6
- Move `I2Cpp.Thread::current` to `Il2Cpp::currentThread`.
- Move `I2Cpp.Thread::all` to `Il2Cpp::attachedThreads`.
- Add `Il2Cpp::sheduleOnInitializerThread` to run a callback inside the main Il2Cpp thread instead of Frida's one.

### 0.7.5
- Fix #66 and #95.

### 0.7.4
- `Il2Cpp.Method::restoreImplementation` was renamed to `Il2Cpp.Method::revert`.
- `Il2Cpp.Tracer` api change:
  ```ts
  Il2Cpp.perform(() => {
    Il2Cpp.trace()
        .classes(Il2Cpp.Image.corlib.class("System.String"))
        .and()
        .attach("detailed");
  });
  ```

### 0.7.3
- `Il2Cpp.Thread::id` was added.
- `Il2Cpp::perform` can now return a value:
  ```ts
  async function foo() {
      const result = await Il2Cpp.perform<string>(() => {
          const SystemBoolean = Il2Cpp.Image.corlib.class("System.Boolean");
          return SystemBoolean.field("TrueLiteral").value.toString();
      });

      console.log(`Result from Il2Cpp: ${result}`);

      // ...
  }
  ```

### 0.7.2
- `Il2Cpp::internalCall`, `Il2Cpp::applicationDataPath`, `Il2Cpp::applicationIdentifier`, `Il2Cpp::applicationVersion`, `Il2Cpp::unityVersion` were added.
- `unity` TS module was removed as it was quite useless now that I don't need to interact with Unity native module anymore.
- `Il2Cpp.Dumper` was removed as it was just boilerplate code - `Il2Cpp::dump` gets the exact same job done. `Il2Cpp.Dumper::methods` is gone - I'll provide a snippet to extract methods from the classic dump.
- `Il2Cpp.Api` will not give any hint about the required version when an export isn't found.

### 0.7.1
- Support Unity version up to 2022.1.x. Note: `Il2Cpp.GC::choose` makes the application crash in applications whose Unity version is above 2021.1.
- `Il2Cpp.Class::toString`, `Il2Cpp.Field::toString` and `Il2Cpp.Method::toString` are now implemented in JavaScript. I know this is a considerable performance loss, but the C code looks much simpler now as less logic is involved, also dumping is actually performed once per application, so it's not a total drama.
- `Il2Cpp.Class::interfaceCount`, `Il2Cpp.Class::fieldCount` and `Il2Cpp.Class::methodCount` were removed because unnecessary.
- Faster Unity version detection: the memory isn't scanned anymore, the proper function is invoked instead.

### 0.7.0
- `Il2Cpp.Domain::assemblies`, `Il2Cpp.Image::classes`, `Il2Cpp.Class::methods` and so on now return a plain simple array.
- `Il2Cpp.Domain::assembly`, `Il2Cpp.Image::class`, `Il2Cpp.Class::method` and so on were added to obtain an item with the given name. They are all equivalent to the old accessor way:
  ```ts
  // old
  const mscorlib = Il2Cpp.Domain.assemblies.mscorlib.image;
  const SystemString = mscorlib.classes["System.String"];
  
  // new
  const mscorlib = Il2Cpp.Domain.assembly("mscorlib").image;
  const SystemString = mscorlib.class("System.String");
  ```
  The new look is more consistent and easier to manage and has a positive noticeable impact on performance (e.g. there's no need to find all classes first). Lastly, but not least importantly, there's no need to cast an object to its base when trying to invoke a base method or accessing a base class!
  
  However, there are a couple of important changes:
  - Nested classes must be accessed within their declaring class via `Il2Cpp.Class::nested`:
    ```ts
    // old
    const TransitionTime = mscorlib.classes["System.TimeZoneInfo.TransitionTime"];

    // new
    const TransitionTime = mscorlib.class("System.TimeZoneInfo").nested("TransitionTime");
    ```
  - Generic type parameters must follow IL convention, so `<T1, ... TN>` becomes `` `N `` when calling `Il2Cpp.Image::class` or `Il2Cpp.Image::tryClass`:
    ```ts
    // old
    const List = mscorlib.classes["System.Collections.Generic.List<T>"];

    // new
    const List = mscorlib.class("System.Collections.Generic.List`1");
    ```

- `Il2Cpp.Method::overload` was added to help picking the correct method with the given parameter type names.
- `Il2Cpp.Object::base` was removed because it's not necessary anymore.
- `Il2Cpp.Method::implement` does not artificially cast instances to the method declaring class anymore.
- `Il2Cpp.Method::invoke` doesn't try to catch C# exceptions anymore: the solutions I adopted (= catch `abort was called` error) is unreliable and inconsistent.
- `Il2Cpp.Field` and `Il2Cpp.Method` now have type parameters:
  ```ts
  const SystemBoolean = Il2Cpp.Image.corlib.class("System.Boolean");

  const TrueLiteral = SystemBoolean.field<Il2Cpp.String>("TrueLiteral");
  TrueLiteral.value = 23; // type error!

  const Parse = SystemBoolean.method<boolean>("Parse");
  const result = Parse.invoke(Il2Cpp.String.from("true"));
  ```
  In `Il2Cpp.Method` the type parameter was moved out from `invoke`. Type parameters for method arguments aren't present because they add too much verbosity for little benefit.

## Acknowledgements
Thanks to [meme](https://github.com/meme) and [knobse](https://github.com/knobse) for helping and getting me into this, 
and to [djkaty](https://github.com/djkaty) and [nneonneo](https://github.com/nneonneo) for providing the Il2Cpp
api.

## Problems?

Discussions and Wiki are both active. Use them!