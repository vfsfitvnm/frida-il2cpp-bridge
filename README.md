# frida-il2cpp-bridge

[![Frida](https://img.shields.io/badge/-frida-ef6456?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyAgIHZlcnNpb249IjEuMSIgICBpZD0iTGF5ZXJfMSIgICB4PSIwcHgiICAgeT0iMHB4IiAgIHZpZXdCb3g9IjAgMCA5LjcyOTk3OTkgMTAuOTM1NzEyIiAgIGVuYWJsZS1iYWNrZ3JvdW5kPSJuZXcgMCAwIDIwNC40IDM5IiAgIHhtbDpzcGFjZT0icHJlc2VydmUiICAgc29kaXBvZGk6ZG9jbmFtZT0ibG9nby5zdmciICAgd2lkdGg9IjkuNzI5OTc5NSIgICBoZWlnaHQ9IjEwLjkzNTcxMiIgICBpbmtzY2FwZTp2ZXJzaW9uPSIxLjEgKGNlNjY2M2IzYjcsIDIwMjEtMDUtMjUpIiAgIHhtbG5zOmlua3NjYXBlPSJodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy9uYW1lc3BhY2VzL2lua3NjYXBlIiAgIHhtbG5zOnNvZGlwb2RpPSJodHRwOi8vc29kaXBvZGkuc291cmNlZm9yZ2UubmV0L0RURC9zb2RpcG9kaS0wLmR0ZCIgICB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnMgICBpZD0iZGVmczkiIC8+PHNvZGlwb2RpOm5hbWVkdmlldyAgIGlkPSJuYW1lZHZpZXc3IiAgIHBhZ2Vjb2xvcj0iI2ZmZmZmZiIgICBib3JkZXJjb2xvcj0iIzY2NjY2NiIgICBib3JkZXJvcGFjaXR5PSIxLjAiICAgaW5rc2NhcGU6cGFnZXNoYWRvdz0iMiIgICBpbmtzY2FwZTpwYWdlb3BhY2l0eT0iMC4wIiAgIGlua3NjYXBlOnBhZ2VjaGVja2VyYm9hcmQ9IjAiICAgc2hvd2dyaWQ9ImZhbHNlIiAgIGZpdC1tYXJnaW4tdG9wPSIwIiAgIGZpdC1tYXJnaW4tbGVmdD0iMCIgICBmaXQtbWFyZ2luLXJpZ2h0PSIwIiAgIGZpdC1tYXJnaW4tYm90dG9tPSIwIiAgIGlua3NjYXBlOnpvb209IjYuOTE3ODA4NCIgICBpbmtzY2FwZTpjeD0iLTAuMTQ0NTU0NDUiICAgaW5rc2NhcGU6Y3k9Ii04LjYwMDk4OTkiICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxOTIwIiAgIGlua3NjYXBlOndpbmRvdy1oZWlnaHQ9IjEwMDgiICAgaW5rc2NhcGU6d2luZG93LXg9IjAiICAgaW5rc2NhcGU6d2luZG93LXk9IjAiICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSIgICBpbmtzY2FwZTpjdXJyZW50LWxheWVyPSJMYXllcl8xIiAvPjxnICAgaWQ9Imc0IiAgIHN0eWxlPSJkaXNwbGF5OmlubGluZTtmaWxsOiNmZmZmZmYiICAgdHJhbnNmb3JtPSJtYXRyaXgoMC4yODA0MDI4NiwwLDAsMC4yODA0MDI4NiwtMTEuNTgwNjM4LDApIj48cGF0aCAgIGZpbGw9IiNmZmZmZmYiICAgZD0iTSA1MS40LDM5IEggNDEuMyBMIDQ5LjcsMjYuMSBDIDQ0LjksMjMuOCA0Mi4zLDE5LjYgNDIuMywxMy41IDQyLjMsNC44IDQ4LjIsMCA1OC41LDAgSCA3NiBWIDM5IEggNjcgViAyOCBIIDU4LjUgNTcuNyBaIE0gNjcsMjAgViA3IGggLTguNSBjIC00LjksMCAtNy43LDIgLTcuNyw2LjQgMCw0LjUgMi44LDYuNiA3LjcsNi42IHoiICAgaWQ9InBhdGgyIiAgIHN0eWxlPSJmaWxsOiNmZmZmZmYiIC8+PC9nPjwvc3ZnPg==)](https://frida.re)
[![NPM](https://img.shields.io/npm/v/frida-il2cpp-bridge?label=&logo=npm&style=for-the-badge)](https://npmjs.org/package/frida-il2cpp-bridge)

A Frida module to dump, trace or hijack any Il2Cpp application at runtime, without needing the `global-metadata.dat` file.

![Screenshot_20210911_121628](https://user-images.githubusercontent.com/46219656/132944635-6fb7d70b-ff4d-457f-9cd5-d9b98f40af9c.png)

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