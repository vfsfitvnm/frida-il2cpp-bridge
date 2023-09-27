Il2Cpp.perform(() => {
    send(`\x1b[94m\x1b[1m►\x1b[22m\x1b[0m ${$EXPECTED_UNITY_VERSION}`);

    test("Il2Cpp::unityVersion", () => {
        assert($EXPECTED_UNITY_VERSION, () => Il2Cpp.unityVersion);
    });

    test("Il2Cpp::currentThread", () => {
        disavow(null, () => Il2Cpp.currentThread);
    });

    test("Il2Cpp.Thread::id", () => {
        assert(Process.getCurrentThreadId(), () => Il2Cpp.currentThread?.id);
    });

    test("Il2Cpp.Domain::handle", () => {
        disavow(NULL, () => Il2Cpp.domain.handle);
    });

    test("Il2Cpp.Domain::assemblies", () => {
        assert(true, () => Il2Cpp.domain.assemblies.length > 0);
    });

    test("Il2Cpp.Domain::object", () => {
        assert(Il2Cpp.corlib.class("System.AppDomain"), () => Il2Cpp.domain.object.class);
    });

    test("Il2Cpp.Domain::tryAssembly", () => {
        disavow(null, () => Il2Cpp.domain.tryAssembly("mscorlib"));
        assert(null, () => Il2Cpp.domain.tryAssembly("howboring"));
        disavow(null, () => Il2Cpp.domain.tryAssembly("GameAssembly"));
    });

    test("Il2Cpp.Domain::assembly", () => {
        throws("couldn't find assembly howboring", () => Il2Cpp.domain.assembly("howboring"));
    });

    test("Il2Cpp.Assembly::name", () => {
        assert("mscorlib", () => Il2Cpp.domain.assembly("mscorlib").name);
    });

    test("Il2Cpp.Assembly::image", () => {
        assert(Il2Cpp.corlib, () => Il2Cpp.domain.assembly("mscorlib").image);
    });

    test("Il2Cpp.Assembly::object", () => {
        assert(true, () => Il2Cpp.domain.assembly("mscorlib").object.class.isSubclassOf(Il2Cpp.corlib.class("System.Reflection.Assembly")));
    });

    test("Il2Cpp::corlib", () => {
        assert(Il2Cpp.domain.assembly("mscorlib").image, () => Il2Cpp.corlib);
    });

    test("Il2Cpp.Image::name", () => {
        assert("mscorlib.dll", () => Il2Cpp.corlib.name);
    });

    test("Il2Cpp.Image::assembly", () => {
        assert(Il2Cpp.domain.assembly("mscorlib"), () => Il2Cpp.corlib.assembly);
    });

    test("Il2Cpp.Image::tryClass", () => {
        assert(null, () => Il2Cpp.corlib.tryClass("System.Boring"));
        disavow(NULL, () => Il2Cpp.corlib.tryClass("System.String")?.handle ?? NULL);
        disavow(NULL, () => Il2Cpp.corlib.tryClass("<Module>")?.handle ?? NULL);
        disavow(NULL, () => Il2Cpp.corlib.tryClass("System.Collections.Generic.List`1")?.handle ?? NULL);
    });

    test("Il2Cpp.Image::class", () => {
        throws("couldn't find class System.Boring in assembly mscorlib.dll", () => Il2Cpp.corlib.class("System.Boring"));
    });

    test("Il2Cpp.Image::classes", () => {
        assert(true, () => Il2Cpp.corlib.classes.length > 0);
        assert(true, () => Il2Cpp.domain.assembly("GameAssembly").image.classes.length > 0);
    });

    test("Il2Cpp.Image::classCount", () => {
        assert(13, () => Il2Cpp.domain.assembly("GameAssembly").image.classes.length);
        assert(13, () => Il2Cpp.domain.assembly("GameAssembly").image.classCount);
    });

    test("Il2Cpp.Class::image", () => {
        assert(Il2Cpp.corlib, () => Il2Cpp.corlib.class("System.String").image);
    });

    test("Il2Cpp.Class::assemblyName", () => {
        assert("mscorlib", () => Il2Cpp.corlib.class("System.String").assemblyName);
    });

    test("Il2Cpp.Class::actualInstanceSize", () => {
        assert(1, () => Il2Cpp.corlib.class("<Module>").actualInstanceSize);
        assert(Il2Cpp.Object.headerSize, () => Il2Cpp.corlib.class("System.Void").actualInstanceSize);
        assert(Il2Cpp.Object.headerSize + 4, () => Il2Cpp.corlib.class("System.Int32").actualInstanceSize);
    });

    test("Il2Cpp.Class::arrayElementSize", () => {
        assert(0, () => Il2Cpp.corlib.class("System.Void").arrayElementSize);
        assert(1, () => Il2Cpp.corlib.class("System.Byte").arrayElementSize);
        assert(4, () => Il2Cpp.corlib.class("System.Int32").arrayElementSize);
        assert(8, () => Il2Cpp.corlib.class("System.String").arrayElementSize);
    });

    test("Il2Cpp.Class::name", () => {
        assert("String", () => Il2Cpp.corlib.class("System.String").name);
        assert("List`1", () => Il2Cpp.corlib.class("System.Collections.Generic.List`1").name);
    });

    test("Il2Cpp.Class::namespace", () => {
        assert("System", () => Il2Cpp.corlib.class("System.String").namespace);
        assert("System.Collections.Generic", () => Il2Cpp.corlib.class("System.Collections.Generic.List`1").namespace);
        assert("", () => Il2Cpp.corlib.class("<Module>").namespace);
    });

    test("Il2Cpp.Class::fullname", () => {
        assert("System.String", () => Il2Cpp.corlib.class("System.String").fullName);
        assert("System.Collections.Generic.List`1", () => Il2Cpp.corlib.class("System.Collections.Generic.List`1").fullName);
        assert("<Module>", () => Il2Cpp.corlib.class("<Module>").fullName);
    });

    test("Il2Cpp.Class::type", () => {
        disavow(NULL, () => Il2Cpp.corlib.class("System.String").type);
    });

    test("Il2Cpp.Class::isAbstract", () => {
        assert(false, () => Il2Cpp.corlib.class("System.String").isAbstract);
        assert(true, () => Il2Cpp.corlib.class("System.IComparable").isAbstract);
        assert(true, () => Il2Cpp.domain.assembly("GameAssembly").image.class("AbstractGenericClass`2").isAbstract);
        assert(false, () => Il2Cpp.domain.assembly("GameAssembly").image.class("PartiallyInflatedClass`1").isAbstract);
    });

    test("Il2Cpp.Class::isEnum", () => {
        assert(false, () => Il2Cpp.corlib.class("System.String").isEnum);
        assert(false, () => Il2Cpp.corlib.class("System.Boolean").isEnum);
        assert(true, () => Il2Cpp.corlib.class("System.DayOfWeek").isEnum);
    });

    test("Il2Cpp.Class::isValueType", () => {
        assert(false, () => Il2Cpp.corlib.class("System.String").isValueType);
        assert(true, () => Il2Cpp.corlib.class("System.Boolean").isValueType);
        assert(true, () => Il2Cpp.corlib.class("System.DayOfWeek").isValueType);
    });

    test("Il2Cpp.Class::isGeneric", () => {
        assert(false, () => Il2Cpp.corlib.class("System.String").isGeneric);
        assert(true, () => Il2Cpp.corlib.class("System.Collections.Generic.List`1").isGeneric);
    });

    test("Il2Cpp.Class::inflate", () => {
        throws("cannot inflate class System.String as it has no generic parameters", () => Il2Cpp.corlib.class("System.String").inflate());
        throws("cannot inflate class System.Collections.Generic.List<T> as it needs 1 generic parameter(s), not 0", () => {
            return Il2Cpp.corlib.class("System.Collections.Generic.List`1").inflate();
        });
        disavow(NULL, () => {
            return Il2Cpp.corlib.class("System.Action`1").inflate(Il2Cpp.corlib.class("System.String"));
        });
    });

    test("Il2Cpp.Class::isInflated", () => {
        assert(false, () => Il2Cpp.corlib.class("System.String").isInflated);
        assert(false, () => Il2Cpp.corlib.class("System.Action`1").isInflated);
        assert(true, () => Il2Cpp.corlib.class("System.Action`1").inflate(Il2Cpp.corlib.class("System.String")).isInflated);
    });

    test("Il2Cpp.Class::isInterface", () => {
        assert(false, () => Il2Cpp.corlib.class("System.String").isInterface);
        assert(true, () => Il2Cpp.corlib.class("System.IComparable").isInterface);
        assert(false, () => Il2Cpp.domain.assembly("GameAssembly").image.class("AbstractGenericClass`2").isInterface);
        assert(false, () => Il2Cpp.domain.assembly("GameAssembly").image.class("PartiallyInflatedClass`1").isInterface);
    });

    test("Il2Cpp.Class::declaringClass", () => {
        assert(null, () => Il2Cpp.corlib.class("System.Array").declaringClass);
        assert(Il2Cpp.corlib.class("System.Threading.Timer"), () => {
            return Il2Cpp.corlib.class("System.Threading.Timer").nested("Scheduler").declaringClass;
        });
    });

    test("Il2Cpp.Class::arrayClass", () => {
        assert("String[]", () => Il2Cpp.corlib.class("System.String").arrayClass.name);
        assert("String[][]", () => Il2Cpp.corlib.class("System.String").arrayClass.arrayClass.name);
    });

    test("Il2Cpp.Class::elementClass", () => {
        const Method = () => Il2Cpp.domain.assembly("GameAssembly").image.class("Class").method("Method");

        assert(Il2Cpp.corlib.class("System.Boolean"), () => Il2Cpp.corlib.class("System.Boolean").arrayClass.elementClass);
        assert(Il2Cpp.corlib.class("System.Boolean"), () => Method().parameter("pointer").type.class.elementClass);
        assert(Il2Cpp.corlib.class("System.Boolean"), () => Method().parameter("reference").type.class.elementClass);
        assert(Il2Cpp.corlib.class("System.Boolean"), () => Method().parameter("array").type.class.elementClass);
    });

    test("Il2Cpp.Class::baseType", () => {
        const Method = () => Il2Cpp.domain.assembly("GameAssembly").image.class("Class").method("Method");

        assert(null, () => Il2Cpp.corlib.class("System.Boolean").baseType);
        assert(Il2Cpp.corlib.class("System.Boolean").type, () => Il2Cpp.corlib.class("System.Boolean").arrayClass.baseType);
        assert(Il2Cpp.corlib.class("System.Boolean").arrayClass.type, () => Il2Cpp.corlib.class("System.Boolean").arrayClass.arrayClass.baseType);
        assert(Il2Cpp.corlib.class("System.Int32").type, () => Il2Cpp.corlib.class("System.DayOfWeek").baseType);
        assert(null, () => Method().parameter("reference").type.class.baseType);
        assert(Il2Cpp.corlib.class("System.Boolean").type, () => Method().parameter("pointer").type.class.baseType);
        assert(Il2Cpp.corlib.class("System.Boolean").type, () => Method().parameter("array").type.class.baseType);
    });

    test("Il2Cpp.String::content", () => {
        assert("vfsfitvnm", () => Il2Cpp.string("vfsfitvnm").content);
    });

    test("Il2Cpp.String::length", () => {
        assert(9, () => Il2Cpp.string("vfsfitvnm").length);
    });

    test("Il2Cpp.String::content", () => {
        const string = Il2Cpp.string("vfsfitvnm");
        string.content = "frida-il2cpp-bridge";

        assert("frida-il2cpp-bridge", () => string.content);
        assert(19, () => string.length);
    });

    test("Il2Cpp.String::object", () => {
        assert(Il2Cpp.corlib.class("System.String"), () => Il2Cpp.string("vfsfitvnm").object.class);
    });

    test("Il2Cpp.Array::get", () => {
        assert(-2442, () => {
            const SystemInt32 = Il2Cpp.corlib.class("System.Int32");
            const array = Il2Cpp.array(SystemInt32, [0, -1, 12, 3900, -2442, 99]);
            return array.get(4);
        });
    });

    test("Il2Cpp.Array::set", () => {
        assert(2147483647, () => {
            const SystemInt32 = Il2Cpp.corlib.class("System.Int32");
            const array = Il2Cpp.array(SystemInt32, [0, -1, 12, 3900, -2442, 99]);
            array.set(4, 2147483647);
            return array.get(4);
        });
    });

    test("Every enum base type matches its 'value__' field type", () => {
        Il2Cpp.domain.assemblies.forEach(_ => {
            _.image.classes
                .filter(_ => _.isEnum)
                .forEach(_ => {
                    assert(_.field("value__").type.name, () => _.baseType.name);
                });
        });
    });

    test("Structs fields are read correctly", () => {
        assert(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.unbox().field("value").value;
        });
    });

    test("Enums fields are read correctly", () => {
        assert(6, () => {
            const saturday = Il2Cpp.corlib.class("System.DayOfWeek").field("Saturday").value;
            return saturday.field("value__").value;
        });
    });

    test("Boxed structs fields are read correctly", () => {
        assert(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.field("value").value;
        });
    });

    test("Boxed structs methods are invoked correctly", () => {
        assert(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.handle.add(runtimeTypeHandle.field("value").offset).readPointer();
        });
        assert(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.method("get_Value").invoke();
        });
        assert("System.RuntimeTypeHandle", () => Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc().toString());
    });

    test("Boxing/unboxing structs works correctly", () => {
        assert(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.unbox().box().unbox().box().field("value").value;
        });
    });

    test("Boxed enums fields are read correctly", () => {
        assert(1, () => {
            const MemberTypes = Il2Cpp.corlib.class("System.Reflection.MemberTypes");
            return MemberTypes.field("Constructor").value.box().field("value__").value;
        });
    });

    send(summary);
});

const summary = { type: "summary", passed: 0, failed: 0 };

function test(name, block) {
    const time = +new Date();
    try {
        block();
        const duration = +new Date() - time;
        send(`  \x1b[32m\x1b[1m✓\x1b[22m ${name}\x1b[0m \x1b[2m${duration}ms\x1b[0m`);
        summary.passed++;
    } catch (e) {
        send(`  \x1b[31m\x1b[1m𐄂\x1b[22m ${name}\n    ${e.message}\x1b[0m`);
        summary.failed++;
    }
}

function eq(a, b) {
    return a instanceof NativePointer || a instanceof NativeStruct
        ? a.equals(b)
        : a instanceof Array || b instanceof Array
        ? JSON.stringify(a) == JSON.stringify(b)
        : a == b;
}

function assert(expected, getActual) {
    const actual = getActual();
    if (!eq(expected, actual)) {
        throw new Error(`${getActual}\n    \x1b[1m${expected}\x1b[22m was expected, but got \x1b[1m${actual}\x1b[22m`);
    }
}

function disavow(unexpected, getActual) {
    const actual = getActual();
    if (eq(unexpected, actual)) {
        throw new Error(`${getActual}\n    \x1b[1m${unexpected}\x1b[22m was not expected`);
    }
}

function throws(expected, block) {
    try {
        block();
        throw new Error("no errors");
    } catch (e) {
        assert(expected, () => e.message.replaceAll(/\x1b\[[^m]+m/g, ""));
    }
}
