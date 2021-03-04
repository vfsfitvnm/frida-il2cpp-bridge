# Changelog

## [0.1.15]

### Fixed
- A couple of typos.

### Changed
- License (now is MIT).
- Dependencies refactoring.

## [0.1.13]

### Added
- `Il2Cpp.allocRawValue` and `Il2Cpp.writeFieldValue` do now handle `Il2Cpp.TypeEnum.SZARRAY`.

### Changed
 - `Il2Cpp` is exposed as a global object again.

## [0.1.12]

### Fixed
- `CModule` implementation of `il2cpp_field_is_literal`.

### Changed
 - `Il2Cpp` is not global anymore.
 
## [0.1.9]

### Changed
 - `Il2Cpp` is not global anymore.

## [0.1.8]

### Added
 - The dump will now include
    literal (constant) values.

### Changed
 - `Il2Cpp.dump` is not async anymore.
 - `Il2Cpp.dump` implementation has been move from `CModule` to pure JS (performance drop).

## [0.1.7]

### Added
 - `Il2Cpp.choose2` to find instances of a given class using another method.
 - Windows support.
 
## [0.1.6]

### Changed
 - Enums are now read as 32-bit signed integers.

## [0.1.5]

- `Il2Cpp.Class.interfaceCount` to get the count of implemented interfaces by a given class.
- `Il2Cpp.Class.interfaces` to get the interfaces implemented by a given class

 ### Changed
 - The dump will now include parents and
    interfaces of each class.

## [0.1.4]

### Added 

- Few example snippets.

## [0.1.3] 

### Changed
 - `Il2Cpp.ValueType`, `Il2Cpp.Object` and `Il2Cpp.String` can now have a `NULL` handle.

## [0.1.1] 

### Added
 - `Il2Cpp.choose` to find instances of a given class.
 - `Il2Cpp.Image.getClassFromName` to retrieve a class from its name.
 - `Il2Cpp.Class.arrayClass` to get the array class of the given class.
 
### Changed
 - `Il2Cpp.Class.ensureInitialized` will now call the api `il2cpp_runtime_class_init` instead of calling its static
  constructor explicitly.


[0.1.15]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/60c4ac7..HEAD
[0.1.13]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/fe8e02a..60c4ac7
[0.1.12]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/a6a202a..fe8e02a
[0.1.9]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/4d1a678..a6a202a
[0.1.8]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/667237d..4d1a678
[0.1.7]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/fae6029..667237d
[0.1.6]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/4502c50..fae6029
[0.1.5]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/a0e8652..4502c50
[0.1.4]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/5cc7c99..a0e8652
[0.1.3]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/31673d1..5cc7c99
[0.1.1]: https://github.com/vfsfitvnm/frida-il2cpp-bridge/compare/3c12b51..31673d1