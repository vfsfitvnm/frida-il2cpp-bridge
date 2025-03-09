Il2Cpp.perform(() => {
    send(`\x1b[94m\x1b[1m►\x1b[22m\x1b[0m ${$EXPECTED_UNITY_VERSION}`);

    test("Il2Cpp::unityVersion", () => {
        assertEquals($EXPECTED_UNITY_VERSION, () => Il2Cpp.unityVersion);
    });

    test("Il2Cpp::currentThread", () => {
        assertNotNull(() => Il2Cpp.currentThread);
    });

    test("Il2Cpp.Thread::id", () => {
        assertEquals(Process.getCurrentThreadId(), () => Il2Cpp.currentThread?.id);
    });

    test("Il2Cpp.Domain::handle", () => {
        assertNotEquals(NULL, () => Il2Cpp.domain.handle);
    });

    test("Il2Cpp.Domain::assemblies", () => {
        assertTrue(() => Il2Cpp.domain.assemblies.length > 0);
    });

    test("Il2Cpp.Domain::object", () => {
        assertEquals(Il2Cpp.corlib.class("System.AppDomain"), () => Il2Cpp.domain.object.class);
    });

    test("Il2Cpp.Domain::tryAssembly", () => {
        assertNotNull(() => Il2Cpp.domain.tryAssembly("mscorlib"));
        assertNull(() => Il2Cpp.domain.tryAssembly("howboring"));
        assertNotNull(() => Il2Cpp.domain.tryAssembly("GameAssembly"));
    });

    test("Il2Cpp.Domain::assembly", () => {
        assertThrows("couldn't find assembly howboring", () => Il2Cpp.domain.assembly("howboring"));
    });

    test("Il2Cpp.Assembly::name", () => {
        assertEquals("mscorlib", () => Il2Cpp.domain.assembly("mscorlib").name);
    });

    test("Il2Cpp.Assembly::image", () => {
        assertEquals(Il2Cpp.corlib, () => Il2Cpp.domain.assembly("mscorlib").image);
    });

    test("Il2Cpp.Assembly::object", () => {
        assertTrue(() => Il2Cpp.domain.assembly("mscorlib").object.class.isSubclassOf(Il2Cpp.corlib.class("System.Reflection.Assembly")));
    });

    test("Il2Cpp::corlib", () => {
        assertEquals(Il2Cpp.domain.assembly("mscorlib").image, () => Il2Cpp.corlib);
    });

    test("Il2Cpp.Image::name", () => {
        assertEquals("mscorlib.dll", () => Il2Cpp.corlib.name);
    });

    test("Il2Cpp.Image::assembly", () => {
        assertEquals(Il2Cpp.domain.assembly("mscorlib"), () => Il2Cpp.corlib.assembly);
    });

    test("Il2Cpp.Image::tryClass", () => {
        assertNull(() => Il2Cpp.corlib.tryClass("System.Boring"));
        assertNotEquals(NULL, () => Il2Cpp.corlib.tryClass("System.String")?.handle ?? NULL);
        assertNotEquals(NULL, () => Il2Cpp.corlib.tryClass("<Module>")?.handle ?? NULL);
        assertNotEquals(NULL, () => Il2Cpp.corlib.tryClass("System.Collections.Generic.List`1")?.handle ?? NULL);
    });

    test("Il2Cpp.Image::class", () => {
        assertThrows("couldn't find class System.Boring in assembly mscorlib.dll", () => Il2Cpp.corlib.class("System.Boring"));
    });

    test("Il2Cpp.Image::classes", () => {
        assertTrue(() => Il2Cpp.corlib.classes.length > 0);
        assertTrue(() => Il2Cpp.domain.assembly("GameAssembly").image.classes.length > 0);
    });

    test("Il2Cpp.Image::classCount", () => {
        assertEquals(27, () => Il2Cpp.domain.assembly("GameAssembly").image.classes.length);
        assertEquals(27, () => Il2Cpp.domain.assembly("GameAssembly").image.classCount);
    });

    test("Il2Cpp.Class::image", () => {
        assertEquals(Il2Cpp.corlib, () => Il2Cpp.corlib.class("System.String").image);
    });

    test("Il2Cpp.Class::assemblyName", () => {
        assertEquals("mscorlib", () => Il2Cpp.corlib.class("System.String").assemblyName);
    });

    test("Il2Cpp.Class::actualInstanceSize", () => {
        assertEquals(1, () => Il2Cpp.corlib.class("<Module>").actualInstanceSize);
        assertEquals(Il2Cpp.Object.headerSize, () => Il2Cpp.corlib.class("System.Void").actualInstanceSize);
        assertEquals(Il2Cpp.Object.headerSize + 4, () => Il2Cpp.corlib.class("System.Int32").actualInstanceSize);
    });

    test("Il2Cpp.Class::arrayElementSize", () => {
        assertEquals(0, () => Il2Cpp.corlib.class("System.Void").arrayElementSize);
        assertEquals(1, () => Il2Cpp.corlib.class("System.Byte").arrayElementSize);
        assertEquals(4, () => Il2Cpp.corlib.class("System.Int32").arrayElementSize);
        assertEquals(8, () => Il2Cpp.corlib.class("System.String").arrayElementSize);
    });

    test("Il2Cpp.Class::name", () => {
        assertEquals("String", () => Il2Cpp.corlib.class("System.String").name);
        assertEquals("List`1", () => Il2Cpp.corlib.class("System.Collections.Generic.List`1").name);
    });

    test("Il2Cpp.Class::namespace", () => {
        assertEquals("System", () => Il2Cpp.corlib.class("System.String").namespace);
        assertEquals("System.Collections.Generic", () => Il2Cpp.corlib.class("System.Collections.Generic.List`1").namespace);
        assertEquals("", () => Il2Cpp.corlib.class("<Module>").namespace);
    });

    test("Il2Cpp.Class::fullname", () => {
        assertEquals("System.String", () => Il2Cpp.corlib.class("System.String").fullName);
        assertEquals("System.Collections.Generic.List`1", () => Il2Cpp.corlib.class("System.Collections.Generic.List`1").fullName);
        assertEquals("<Module>", () => Il2Cpp.corlib.class("<Module>").fullName);
    });

    test("Il2Cpp.Class::type", () => {
        assertNotEquals(NULL, () => Il2Cpp.corlib.class("System.String").type);
    });

    test("Il2Cpp.Class::isAbstract", () => {
        assertFalse(() => Il2Cpp.corlib.class("System.String").isAbstract);
        assertTrue(() => Il2Cpp.corlib.class("System.IComparable").isAbstract);
        assertTrue(() => Il2Cpp.domain.assembly("GameAssembly").image.class("AbstractGenericClass`2").isAbstract);
        assertFalse(() => Il2Cpp.domain.assembly("GameAssembly").image.class("PartiallyInflatedClass`1").isAbstract);
    });

    test("Il2Cpp.Class::isEnum", () => {
        assertFalse(() => Il2Cpp.corlib.class("System.String").isEnum);
        assertFalse(() => Il2Cpp.corlib.class("System.Boolean").isEnum);
        assertTrue(() => Il2Cpp.corlib.class("System.DayOfWeek").isEnum);
    });

    test("Il2Cpp.Class::isValueType", () => {
        assertFalse(() => Il2Cpp.corlib.class("System.String").isValueType);
        assertTrue(() => Il2Cpp.corlib.class("System.Boolean").isValueType);
        assertTrue(() => Il2Cpp.corlib.class("System.DayOfWeek").isValueType);
    });

    test("Il2Cpp.Class::isGeneric", () => {
        assertFalse(() => Il2Cpp.corlib.class("System.String").isGeneric);
        assertTrue(() => Il2Cpp.corlib.class("System.Collections.Generic.List`1").isGeneric);
    });

    test("Il2Cpp.Class::inflate", () => {
        assertThrows("cannot inflate class System.String as it has no generic parameters", () => Il2Cpp.corlib.class("System.String").inflate());
        assertThrows("cannot inflate class System.Collections.Generic.List<T> as it needs 1 generic parameter(s), not 0", () => {
            return Il2Cpp.corlib.class("System.Collections.Generic.List`1").inflate();
        });
        assertNotEquals(NULL, () => {
            return Il2Cpp.corlib.class("System.Action`1").inflate(Il2Cpp.corlib.class("System.String"));
        });
    });

    test("Il2Cpp.Class::isInflated", () => {
        assertFalse(() => Il2Cpp.corlib.class("System.String").isInflated);
        assertFalse(() => Il2Cpp.corlib.class("System.Action`1").isInflated);
        assertTrue(() => Il2Cpp.corlib.class("System.Action`1").inflate(Il2Cpp.corlib.class("System.String")).isInflated);
    });

    test("Il2Cpp.Class::isInterface", () => {
        assertFalse(() => Il2Cpp.corlib.class("System.String").isInterface);
        assertTrue(() => Il2Cpp.corlib.class("System.IComparable").isInterface);
        assertFalse(() => Il2Cpp.domain.assembly("GameAssembly").image.class("AbstractGenericClass`2").isInterface);
        assertFalse(() => Il2Cpp.domain.assembly("GameAssembly").image.class("PartiallyInflatedClass`1").isInterface);
    });

    test("Il2Cpp.Class::declaringClass", () => {
        assertNull(() => Il2Cpp.corlib.class("System.Array").declaringClass);
        assertEquals(Il2Cpp.corlib.class("System.Threading.Timer"), () => {
            return Il2Cpp.corlib.class("System.Threading.Timer").nested("Scheduler").declaringClass;
        });
    });

    test("Il2Cpp.Class::arrayClass", () => {
        assertEquals("String[]", () => Il2Cpp.corlib.class("System.String").arrayClass.name);
        assertEquals("String[][]", () => Il2Cpp.corlib.class("System.String").arrayClass.arrayClass.name);
    });

    test("Il2Cpp.Class::elementClass", () => {
        const Method = () => Il2Cpp.domain.assembly("GameAssembly").image.class("Class").method("Method");

        assertEquals(Il2Cpp.corlib.class("System.Boolean"), () => Il2Cpp.corlib.class("System.Boolean").arrayClass.elementClass);
        assertEquals(Il2Cpp.corlib.class("System.Boolean"), () => Method().parameter("pointer").type.class.elementClass);
        assertEquals(Il2Cpp.corlib.class("System.Boolean"), () => Method().parameter("reference").type.class.elementClass);
        assertEquals(Il2Cpp.corlib.class("System.Boolean"), () => Method().parameter("array").type.class.elementClass);
    });

    test("Il2Cpp.Class::baseType", () => {
        const Method = () => Il2Cpp.domain.assembly("GameAssembly").image.class("Class").method("Method");

        assertNull(() => Il2Cpp.corlib.class("System.Boolean").baseType);
        assertEquals(Il2Cpp.corlib.class("System.Boolean").type, () => Il2Cpp.corlib.class("System.Boolean").arrayClass.baseType);
        assertEquals(Il2Cpp.corlib.class("System.Boolean").arrayClass.type, () => Il2Cpp.corlib.class("System.Boolean").arrayClass.arrayClass.baseType);
        assertEquals(Il2Cpp.corlib.class("System.Int32").type, () => Il2Cpp.corlib.class("System.DayOfWeek").baseType);
        assertNull(() => Method().parameter("reference").type.class.baseType);
        assertEquals(Il2Cpp.corlib.class("System.Boolean").type, () => Method().parameter("pointer").type.class.baseType);
        assertEquals(Il2Cpp.corlib.class("System.Boolean").type, () => Method().parameter("array").type.class.baseType);
    });

    test("Il2Cpp.String::content", () => {
        assertEquals("vfsfitvnm", () => Il2Cpp.string("vfsfitvnm").content);
    });

    test("Il2Cpp.String::length", () => {
        assertEquals(9, () => Il2Cpp.string("vfsfitvnm").length);
    });

    test("Il2Cpp.String::content", () => {
        const string = Il2Cpp.string("vfsfitvnm");
        string.content = "frida-il2cpp-bridge";

        assertEquals("frida-il2cpp-bridge", () => string.content);
        assertEquals(19, () => string.length);
    });

    test("Il2Cpp.String::object", () => {
        assertEquals(Il2Cpp.corlib.class("System.String"), () => Il2Cpp.string("vfsfitvnm").object.class);
    });

    test("Il2Cpp.Array::get", () => {
        assertEquals(-2442, () => {
            const SystemInt32 = Il2Cpp.corlib.class("System.Int32");
            const array = Il2Cpp.array(SystemInt32, [0, -1, 12, 3900, -2442, 99]);
            return array.get(4);
        });
    });

    test("Il2Cpp.Array::set", () => {
        assertEquals(2147483647, () => {
            const SystemInt32 = Il2Cpp.corlib.class("System.Int32");
            const array = Il2Cpp.array(SystemInt32, [0, -1, 12, 3900, -2442, 99]);
            array.set(4, 2147483647);
            return array.get(4);
        });
    });

    test("Il2Cpp.Object field lookup ignores static fields", () => {
        const Class = Il2Cpp.domain.assembly("GameAssembly").image.class("Il2CppObjectTest");

        assertNull(() => Class.new().tryField("F"));
        assertThrows("couldn't find non-static field F in class Il2CppObjectTest", () => Class.new().field("F"));
    });

    test("Il2Cpp.Object method lookup ignores static methods", () => {
        const Class = Il2Cpp.domain.assembly("GameAssembly").image.class("Il2CppObjectTest");

        assertNotNull(() => Class.new().tryMethod("A"));
        assertNull(() => Class.new().tryMethod("B"));
        assertNull(() => Class.new().tryMethod("C", 1));
        assertNotNull(() => Class.new().tryMethod("C"));
        assertNotNull(() => Class.new().tryMethod("C", 0));

        assertEquals(1, () => Class.new().method("A").invoke(NULL));
        assertThrows("couldn't find non-static method B in class Il2CppObjectTest", () => Class.new().method("B"));
    });

    test("Every enum base type matches its 'value__' field type", () => {
        Il2Cpp.domain.assemblies.forEach(_ => {
            _.image.classes
                .filter(_ => _.isEnum)
                .forEach(_ => {
                    assertEquals(_.field("value__").type.name, () => _.baseType.name);
                });
        });
    });

    test("Structs fields are read correctly", () => {
        assertEquals(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.unbox().field("value").value;
        });
    });

    test("Enums fields are read correctly", () => {
        assertEquals(6, () => {
            const saturday = Il2Cpp.corlib.class("System.DayOfWeek").field("Saturday").value;
            return saturday.field("value__").value;
        });
    });

    test("Boxed structs fields are read correctly", () => {
        assertEquals(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.field("value").value;
        });
    });

    test("Boxed structs methods are invoked correctly", () => {
        assertEquals(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.handle.add(runtimeTypeHandle.field("value").offset).readPointer();
        });
        assertEquals(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.method("get_Value").invoke();
        });
        assertEquals("System.RuntimeTypeHandle", () => Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc().toString());
    });

    test("Structs methods are invoked correctly", () => {
        assertEquals(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc().unbox();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.method("get_Value").invoke();
        });
        assertEquals("System.RuntimeTypeHandle", () => Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc().toString());
    });

    test("Boxing/unboxing structs works correctly", () => {
        assertEquals(ptr(0xdeadbeef), () => {
            const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
            runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));
            return runtimeTypeHandle.unbox().box().unbox().box().field("value").value;
        });
    });

    test("Boxed enums fields are read correctly", () => {
        assertEquals(1, () => {
            const MemberTypes = Il2Cpp.corlib.class("System.Reflection.MemberTypes");
            return MemberTypes.field("Constructor").value.box().field("value__").value;
        });
    });

    test("Il2Cpp.Field::value::get (static)", () => {
        assertEquals(46, () => Il2Cpp.corlib.class("System.Type").initialize().field("Delimiter").value);
        assertEquals("Second", () => Il2Cpp.domain.assembly("GameAssembly").image.class("Class").initialize().field("enumfield").value.toString());
        assertEquals("79228162514264337593543950335", () => Il2Cpp.corlib.class("System.Decimal").initialize().field("MaxValue").value.toString());
        assertEquals("True", () => Il2Cpp.corlib.class("System.Boolean").initialize().field("TrueString").value.content);
    });

    test("Il2Cpp.Field::value::set (static)", () => {
        assertEquals(48, () => {
            const SystemType = Il2Cpp.corlib.class("System.Type").initialize();
            SystemType.field("Delimiter").value = 48;
            return SystemType.field("Delimiter").value;
        });
        assertEquals(48, () => {
            const SystemType = Il2Cpp.corlib.class("System.Type").initialize();
            const value = SystemType.field("Delimiter").type.class.alloc();
            value.field("m_value").value = 48;
            SystemType.field("Delimiter").value = value;
            return SystemType.field("Delimiter").value;
        });
        assertEquals("Third", () => {
            const Class = Il2Cpp.domain.assembly("GameAssembly").image.class("Class");
            Class.field("enumfield").value = Class.field("enumfield").type.class.field("Third").value;
            return Class.field("enumfield").value.toString();
        });
        assertEquals("123456", () => {
            const SystemDecimal = Il2Cpp.corlib.class("System.Decimal").initialize();
            const value = SystemDecimal.alloc();
            value.method(".ctor", 1).invoke(123456);
            SystemDecimal.field("MaxValue").value = value;
            return SystemDecimal.field("MaxValue").value.toString();
        });
        assertEquals("VeryTrue", () => {
            const SystemBoolean = Il2Cpp.corlib.class("System.Boolean").initialize();
            SystemBoolean.field("TrueString").value = Il2Cpp.string("VeryTrue");
            return SystemBoolean.field("TrueString").value.content;
        });
    });

    test("Invoke a method that returns an enum value", () => {
        assertEquals("Unix", () => Il2Cpp.corlib.class("System.Environment").method("get_Platform").invoke().toString());
    });

    test("Invoke a method that takes an enum value", () => {
        assertEquals("Sunday", () => {
            const DateTimeFormatInfo = Il2Cpp.corlib.class("System.Globalization.DateTimeFormatInfo").initialize();
            const DayOfWeek = Il2Cpp.corlib.class("System.DayOfWeek");
            return DateTimeFormatInfo.new().method("GetDayName").invoke(DayOfWeek.field("Sunday").value).content;
        });
    });

    test("References to value types are created correctly", () => {
        const Decimal = Il2Cpp.corlib.class("System.Decimal").initialize();

        const x = Decimal.alloc().unbox();
        const y = Decimal.alloc().unbox();

        x.method(".ctor").overload("System.Int32").invoke(-1234);
        y.method(".ctor").overload("System.Int32").invoke(777);

        const xRef = Il2Cpp.reference(x);

        assertEquals(1234, () => xRef.handle.add(Decimal.field("lo").offset - Il2Cpp.Object.headerSize).readInt());

        assertEquals(-1, () => {
            const Compare = Decimal.tryMethod("FCallCompare") ?? Decimal.tryMethod("decimalCompare");
            return Compare ? Compare.invoke(xRef, Il2Cpp.reference(y)) : Decimal.method("Sign").invoke(xRef);
        });
    });

    test("Methods are selected by generic parameter count when inflating", () => {
        const Test = Il2Cpp.domain.assembly("GameAssembly").image.class("MethodInflateTest.Parent`1").inflate(Il2Cpp.corlib.class("System.Object"));

        assertEquals(0, () => Test.method("A").inflate(Test).invoke());
        assertEquals(1, () => Test.method("A").inflate(Test, Test).invoke());

        assertEquals(1, () => Test.method("B").inflate(Test).invoke(NULL));
        assertEquals(2, () => Test.method("B").inflate(Test, Test).invoke());

        assertEquals(0, () => Test.method("C").invoke(NULL));
        assertEquals(1, () => Test.method("C").inflate(Test).invoke(NULL));

        assertThrows("could not find inflatable signature of method D with 1 generic parameter(s)", () => Test.method("D").inflate(Test));
        assertThrows("could not find inflatable signature of method C with 2 generic parameter(s)", () => Test.method("C").inflate(Test, Test));
    });

    test("Methods are looked up in parent class when inflating", () => {
        const Test = Il2Cpp.domain.assembly("GameAssembly").image.class("MethodInflateTest.Child");

        assertEquals(0, () => Test.method("A").inflate(Test).invoke());
        assertEquals(1, () => Test.method("B").inflate(Test).invoke(NULL));

        assertEquals(3, () => Test.method("A").inflate(Test, Test, Test).invoke());
    });

    test("Overloading selection picks the correct method", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("OverloadTest");

        assertThrows("couldn't find overloaded method A(A,B)", () => T.new().method("A").overload("A", "B"));
        assertEquals(0, () => T.new().method("A").overload("OverloadTest.Root").invoke(NULL));
        assertEquals(1, () => T.new().method("A").overload("OverloadTest.Child1").invoke(NULL));
        assertNull(() => T.new().method("A").tryOverload("OverloadTest.Child11"));
        assertNull(() => T.new().method("A").tryOverload("OverloadTest.Child2"));
        assertEquals(2, () => T.new().method("A").overload("OverloadTest.Child3").invoke(NULL));
        assertEquals(4, () => T.new().method("A").overload("OverloadTest.Child4<OverloadTest.Root>").invoke(NULL));
        assertNull(() => T.new().method("A").tryOverload("OverloadTest.Child4<T>"));
        assertNull(() => T.new().method("A").tryOverload("OverloadTest.Child4<OverloadTest.Child1>"));
    });

    test("Overloading selection looks in parent class", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("OverloadTest").nested("Nested");

        assertEquals(2, () => T.new().method("C").overload().invoke());
        assertEquals(-1, () => T.new().method("C").overload("System.Int32").invoke(-1));
    });

    test("Overloading selection by type picks the most precise method possible", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("OverloadTest");

        assertEquals(0, () => T.new().method("A").overload(T.nested("Root")).invoke(NULL));
        assertEquals(1, () => T.new().method("A").overload(T.nested("Child1")).invoke(NULL));
        assertEquals(1, () => T.new().method("A").overload(T.nested("Child11")).invoke(NULL));
        assertEquals(0, () => T.new().method("A").overload(T.nested("Child2")).invoke(NULL));
        assertEquals(2, () => T.new().method("A").overload(T.nested("Child3")).invoke(NULL));
        assertEquals(3, () => T.nested("Nested").new().method("A").overload(T.nested("Child2")).invoke(NULL));
        assertEquals(2, () => T.nested("Nested").new().method("A").overload(T.nested("Child3")).invoke(NULL));
        assertEquals(2, () => T.nested("Nested").new().method("A").overload(T.nested("Child311")).invoke(NULL));

        assertEquals(1, () => T.method("E").overload(T.nested("Child1"), T.nested("Child11")).invoke(NULL, NULL));
        assertEquals(ANY, () => T.method("E").overload(T.nested("Child11"), T.nested("Child1")).invoke(NULL, NULL));
        assertEquals(ANY, () => T.method("E").overload(T.nested("Child11"), T.nested("Child11")).invoke(NULL, NULL));
        assertNull(() => T.method("E").tryOverload(T.nested("Child1"), T.nested("Root")));
    });

    test("Overloading instance methods do not select static methods", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("OverloadTest");

        assertNotNull(() => T.method("D").tryOverload("OverloadTest.Child1"));
        assertNull(() => T.new().method("D").tryOverload("OverloadTest.Child1"));
        assertNull(() => T.method("D").tryOverload("OverloadTest.Rooat"));
        assertNull(() => T.new().method("D").tryOverload("OverloadTest.Rot"));
        assertFalse(() => T.method("D").overload("OverloadTest.Root").isStatic);
        assertThrows("couldn't find overloaded method D(OverloadTest.Rooat)", () => T.method("D").overload("OverloadTest.Rooat"));
        assertThrows("couldn't find overloaded method D(OverloadTest.Rot)", () => T.new().method("D").overload("OverloadTest.Rot"));
    });

    send(summary);
});

const summary = { type: "summary", passed: 0, failed: 0, failures: [] };

function test(name, block) {
    const time = +new Date();
    try {
        block();
        const duration = +new Date() - time;
        send(`  \x1b[32m\x1b[1m✓\x1b[22m ${name}\x1b[0m \x1b[2m${duration}ms\x1b[0m`);
        summary.passed++;
    } catch (err) {
        if (err instanceof AssertionError) {
            err.stack = err.stack.trim();
        } else {
            err.stack = err.stack.substr(err.stack.indexOf("\n    at")).trim();
        }
        summary.failures.push(`  \x1b[31m\x1b[1m𐄂\x1b[22m ${name}\x1b[0m\n    \x1b[31m${err.message}\x1b[0m\n    \x1b[31m\x1b[3m\x1b[2m${err.stack}\x1b[0m`);
        summary.failed++;
    }
}

const ANY = {};

function eq(a, b) {
    return a === ANY || b === ANY
        ? true
        : a instanceof NativePointer || a instanceof NativeStruct
        ? a.equals(b)
        : a instanceof Array || b instanceof Array
        ? JSON.stringify(a) == JSON.stringify(b)
        : a == b;
}

function assertEquals(expected, getActual) {
    const actual = getActual();
    if (!eq(expected, actual)) {
        throw new AssertionError(`\x1b[1m${expected}\x1b[22m was expected, but got \x1b[1m${actual}\x1b[22m`, getActual);
    }
}

function assertNotEquals(unexpected, getActual) {
    const actual = getActual();
    if (eq(unexpected, actual)) {
        throw new AssertionError(`\x1b[1m${unexpected}\x1b[22m was not expected`, getActual);
    }
}

function assertTrue(getActual) {
    return assertEquals(true, getActual);
}

function assertFalse(getActual) {
    return assertEquals(false, getActual);
}

function assertNull(getActual) {
    return assertEquals(null, getActual);
}

function assertNotNull(getActual) {
    return assertNotEquals(null, getActual);
}

function assertThrows(expected, block) {
    try {
        block();
        throw new AssertionError("no errors", block);
    } catch (e) {
        assertEquals(expected, () => e.message.replaceAll(/\x1b\[[^m]+m/g, ""));
    }
}

class AssertionError extends Error {
    constructor(message, fn) {
        super(message);
        this.name = "AssertionError";
        this.stack = `\nin ${fn}`;
    }
}
