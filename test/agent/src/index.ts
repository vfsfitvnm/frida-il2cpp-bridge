/// <reference path="../../../lib/index.ts">/>

Script.registerSourceMap("/$UNITY_VERSION.js", new File("$SOURCE_MAP_PATH", "r").readText());

Il2Cpp.perform(() => {
    test("Unity version is detected", () => {
        assert(Il2Cpp.unityVersion).is("$UNITY_VERSION");
    });

    test("Application identifier fallbacks to process name", () => {
        assert(Il2Cpp.application.identifier).is("host");
    });

    test("Application version is detected", () => {
        assert(Il2Cpp.application.version).not(null);
    });

    test("Il2Cpp.Thread::id", () => {
        assert(Il2Cpp.currentThread?.id).is(Process.getCurrentThreadId());
    });

    test("Il2Cpp.Domain::handle", () => {
        assert(Il2Cpp.domain.handle).not(NULL);
    });

    test("Il2Cpp.Domain::assemblies", () => {
        assert(Il2Cpp.domain.assemblies.length > 0).is(true);
    });

    test("Il2Cpp.Domain::object", () => {
        assert(Il2Cpp.domain.object.class).is(Il2Cpp.corlib.class("System.AppDomain"));
    });

    test("Il2Cpp.Domain::tryAssembly", () => {
        assert(Il2Cpp.domain.tryAssembly("mscorlib")).not(null);
        assert(Il2Cpp.domain.tryAssembly("howboring")).is(null);
        assert(Il2Cpp.domain.tryAssembly("GameAssembly")).not(null);
    });

    test("Il2Cpp.Domain::assembly", () => {
        assert(() => Il2Cpp.domain.assembly("howboring")).throws("couldn't find assembly howboring");
    });

    test("Il2Cpp.Assembly::name", () => {
        assert(Il2Cpp.domain.assembly("mscorlib").name).is("mscorlib");
    });

    test("Il2Cpp.Assembly::image", () => {
        assert(Il2Cpp.domain.assembly("mscorlib").image).is(Il2Cpp.corlib);
    });

    test("Il2Cpp.Assembly::object", () => {
        assert(Il2Cpp.domain.assembly("mscorlib").object.class.isSubclassOf(Il2Cpp.corlib.class("System.Reflection.Assembly"), false)).is(true);
    });

    test("Il2Cpp::corlib", () => {
        assert(Il2Cpp.corlib).is(Il2Cpp.domain.assembly("mscorlib").image);
    });

    test("Il2Cpp.Image::name", () => {
        assert(Il2Cpp.corlib.name).is("mscorlib.dll");
    });

    test("Il2Cpp.Image::assembly", () => {
        assert(Il2Cpp.corlib.assembly).is(Il2Cpp.domain.assembly("mscorlib"));
    });

    test("Il2Cpp.Image::tryClass", () => {
        assert(Il2Cpp.corlib.tryClass("System.Boring")).is(null);
        assert(Il2Cpp.corlib.tryClass("System.String")?.handle ?? NULL).not(NULL);
        assert(Il2Cpp.corlib.tryClass("<Module>")?.handle ?? NULL).not(NULL);
        assert(Il2Cpp.corlib.tryClass("System.Collections.Generic.List`1")?.handle ?? NULL).not(NULL);
    });

    test("Il2Cpp.Image::class", () => {
        assert(() => Il2Cpp.corlib.class("System.Boring")).throws("couldn't find class System.Boring in assembly mscorlib.dll");
    });

    test("Il2Cpp.Image::classes", () => {
        assert(Il2Cpp.corlib.classes.length > 0).is(true);
        assert(Il2Cpp.domain.assembly("GameAssembly").image.classes.length > 0).is(true);
    });

    test("Il2Cpp.Image::classCount", () => {
        assert(Il2Cpp.domain.assembly("GameAssembly").image.classes.length).is(32);
        assert(Il2Cpp.domain.assembly("GameAssembly").image.classCount).is(32);
    });

    test("Il2Cpp.Class::image", () => {
        assert(Il2Cpp.corlib.class("System.String").image).is(Il2Cpp.corlib);
    });

    test("Il2Cpp.Class::assemblyName", () => {
        assert(Il2Cpp.corlib.class("System.String").assemblyName).is("mscorlib");
    });

    test("Il2Cpp.Class::actualInstanceSize", () => {
        assert(Il2Cpp.corlib.class("<Module>").actualInstanceSize).is(1);
        assert(Il2Cpp.corlib.class("System.Void").actualInstanceSize).is(Il2Cpp.Object.headerSize);
        assert(Il2Cpp.corlib.class("System.Int32").actualInstanceSize).is(Il2Cpp.Object.headerSize + 4);
    });

    test("Il2Cpp.Class::arrayElementSize", () => {
        assert(Il2Cpp.corlib.class("System.Void").arrayElementSize).is(0);
        assert(Il2Cpp.corlib.class("System.Byte").arrayElementSize).is(1);
        assert(Il2Cpp.corlib.class("System.Int32").arrayElementSize).is(4);
        assert(Il2Cpp.corlib.class("System.String").arrayElementSize).is(8);
    });

    test("Il2Cpp.Class::name", () => {
        assert(Il2Cpp.corlib.class("System.String").name).is("String");
        assert(Il2Cpp.corlib.class("System.Collections.Generic.List`1").name).is("List`1");
    });

    test("Il2Cpp.Class::namespace", () => {
        assert(Il2Cpp.corlib.class("System.String").namespace).is("System");
        assert(Il2Cpp.corlib.class("System.Collections.Generic.List`1").namespace).is("System.Collections.Generic");
        assert(Il2Cpp.corlib.class("<Module>").namespace).is(undefined);
    });

    test("Il2Cpp.Class::fullname", () => {
        assert(Il2Cpp.corlib.class("System.String").fullName).is("System.String");
        assert(Il2Cpp.corlib.class("System.Collections.Generic.List`1").fullName).is("System.Collections.Generic.List`1");
        assert(Il2Cpp.corlib.class("<Module>").fullName).is("<Module>");
    });

    test("Il2Cpp.Class::genericClass", () => {
        const GenericsTest = Il2Cpp.domain.assembly("GameAssembly").image.class("Il2CppClassTest").nested("GenericsTest");
        const List = Il2Cpp.corlib.class("System.Collections.Generic.List`1");

        assert(List.genericClass).is(null);
        assert(List.inflate(Il2Cpp.corlib.class("System.Int32")).genericClass).is(List);
        assert(List.inflate(List).genericClass).is(List);

        assert(GenericsTest.genericClass).is(null);
        assert(GenericsTest.parent!.genericClass).is(List);
    });

    test("Il2Cpp.Class::type", () => {
        assert(Il2Cpp.corlib.class("System.String").type.handle).not(NULL);
    });

    test("Il2Cpp.Class::hierarchy", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("Il2CppClassTest").nested("HierarchyTest");

        assert(Array.from(T.hierarchy())).is([T, T.parent!, T.parent!.parent!]);
        assert(Array.from(T.hierarchy({ includeCurrent: true }))).is([T, T.parent!, T.parent!.parent!]);
        assert(Array.from(T.hierarchy({ includeCurrent: false }))).is([T.parent!, T.parent!.parent!]);

        assert(Array.from(T.parent!.hierarchy())).is([T.parent!, T.parent!.parent!]);
        assert(Array.from(T.parent!.parent!.hierarchy())).is([T.parent!.parent!]);
        assert(Array.from(T.parent!.parent!.hierarchy({ includeCurrent: false }))).is([]);
    });

    test("Il2Cpp.Class::isAbstract", () => {
        assert(Il2Cpp.corlib.class("System.String").isAbstract).is(false);
        assert(Il2Cpp.corlib.class("System.IComparable").isAbstract).is(true);
        assert(Il2Cpp.domain.assembly("GameAssembly").image.class("AbstractGenericClass`2").isAbstract).is(true);
        assert(Il2Cpp.domain.assembly("GameAssembly").image.class("PartiallyInflatedClass`1").isAbstract).is(false);
    });

    test("Il2Cpp.Class::isEnum", () => {
        assert(Il2Cpp.corlib.class("System.String").isEnum).is(false);
        assert(Il2Cpp.corlib.class("System.Boolean").isEnum).is(false);
        assert(Il2Cpp.corlib.class("System.DayOfWeek").isEnum).is(true);
    });

    test("Il2Cpp.Class::isValueType", () => {
        assert(Il2Cpp.corlib.class("System.String").isValueType).is(false);
        assert(Il2Cpp.corlib.class("System.Boolean").isValueType).is(true);
        assert(Il2Cpp.corlib.class("System.DayOfWeek").isValueType).is(true);
    });

    test("Il2Cpp.Class::isGeneric", () => {
        assert(Il2Cpp.corlib.class("System.String").isGeneric).is(false);
        assert(Il2Cpp.corlib.class("System.Collections.Generic.List`1").isGeneric).is(true);
    });

    test("Il2Cpp.Class::inflate", () => {
        assert(() => Il2Cpp.corlib.class("System.String").inflate()).throws("cannot inflate class System.String as it has no generic parameters");
        assert(() => Il2Cpp.corlib.class("System.Collections.Generic.List`1").inflate()).throws(
            "cannot inflate class System.Collections.Generic.List<T> as it needs 1 generic parameter(s), not 0"
        );
        assert(Il2Cpp.corlib.class("System.Action`1").inflate(Il2Cpp.corlib.class("System.String")).handle).not(NULL);
    });

    test("Il2Cpp.Class::isInflated", () => {
        assert(Il2Cpp.corlib.class("System.String").isInflated).is(false);
        assert(Il2Cpp.corlib.class("System.Action`1").isInflated).is(false);
        assert(Il2Cpp.corlib.class("System.Action`1").inflate(Il2Cpp.corlib.class("System.String")).isInflated).is(true);
    });

    test("Il2Cpp.Class::isInterface", () => {
        assert(Il2Cpp.corlib.class("System.String").isInterface).is(false);
        assert(Il2Cpp.corlib.class("System.IComparable").isInterface).is(true);
        assert(Il2Cpp.domain.assembly("GameAssembly").image.class("AbstractGenericClass`2").isInterface).is(false);
        assert(Il2Cpp.domain.assembly("GameAssembly").image.class("PartiallyInflatedClass`1").isInterface).is(false);
    });

    test("Il2Cpp.Class::declaringClass", () => {
        assert(Il2Cpp.corlib.class("System.Array").declaringClass).is(null);
        assert(Il2Cpp.corlib.class("System.Threading.Timer").nested("Scheduler").declaringClass).is(Il2Cpp.corlib.class("System.Threading.Timer"));
    });

    test("Il2Cpp.Class::arrayClass", () => {
        assert(Il2Cpp.corlib.class("System.String").arrayClass.name).is("String[]");
        assert(Il2Cpp.corlib.class("System.String").arrayClass.arrayClass.name).is("String[][]");
    });

    test("Il2Cpp.Class::elementClass", () => {
        const Method = Il2Cpp.domain.assembly("GameAssembly").image.class("Class").method("Method");

        assert(Il2Cpp.corlib.class("System.Boolean").arrayClass.elementClass).is(Il2Cpp.corlib.class("System.Boolean"));
        assert(Method.parameter("pointer").type.class.elementClass).is(Il2Cpp.corlib.class("System.Boolean"));
        assert(Method.parameter("reference").type.class.elementClass).is(Il2Cpp.corlib.class("System.Boolean"));
        assert(Method.parameter("array").type.class.elementClass).is(Il2Cpp.corlib.class("System.Boolean"));
    });

    test("Il2Cpp.Class::pointerClass", () => {
        assert(Il2Cpp.corlib.class("System.Void").pointerClass.name).is("Void*");
        assert(Il2Cpp.corlib.class("System.Boolean").pointerClass.name).is("Boolean*");
        assert(Il2Cpp.corlib.class("System.Boolean").pointerClass.pointerClass.name).is("Boolean**");
        assert(Il2Cpp.domain.assembly("GameAssembly").image.class("Class").pointerClass.name).is("Class*");
    });

    test("Pointer class is declared in the same assembly of its base type", () => {
        assert(Il2Cpp.corlib.class("System.Void").pointerClass.image.assembly).is(Il2Cpp.corlib.assembly);
        assert(Il2Cpp.domain.assembly("GameAssembly").image.class("Class").pointerClass.image.assembly).is(Il2Cpp.domain.assembly("GameAssembly"));
    });

    test("Il2Cpp.Class::baseType", () => {
        const Method = Il2Cpp.domain.assembly("GameAssembly").image.class("Class").method("Method");

        assert(Il2Cpp.corlib.class("System.Boolean").baseType).is(null);
        assert(Il2Cpp.corlib.class("System.Boolean").arrayClass.baseType).is(Il2Cpp.corlib.class("System.Boolean").type);
        assert(Il2Cpp.corlib.class("System.Boolean").arrayClass.arrayClass.baseType).is(Il2Cpp.corlib.class("System.Boolean").arrayClass.type);
        assert(Il2Cpp.corlib.class("System.DayOfWeek").baseType).is(Il2Cpp.corlib.class("System.Int32").type);
        assert(Method.parameter("reference").type.class.baseType).is(null);
        assert(Method.parameter("pointer").type.class.baseType).is(Il2Cpp.corlib.class("System.Boolean").type);
        assert(Method.parameter("array").type.class.baseType).is(Il2Cpp.corlib.class("System.Boolean").type);
    });

    test("Il2Cpp.Type::ENUM.VAR is assigned to generic parameters in a generic type definition", () => {
        assert(Il2Cpp.corlib.class("System.Action`1").generics[0].type.enumValue).is(Il2Cpp.Type.Enum.VAR);
        assert(
            Il2Cpp.domain
                .assembly("GameAssembly")
                .image.class("AbstractGenericClass`2")
                .generics.map(_ => _.type.enumValue)
        ).is([Il2Cpp.Type.Enum.VAR, Il2Cpp.Type.Enum.VAR]);
    });

    test("Il2Cpp.Type::ENUM.MVAR is assigned to generic parameters in a generic method definition", () => {
        assert(Il2Cpp.corlib.class("System.Array").method("AsReadOnly").generics[0].type.enumValue).is(Il2Cpp.Type.Enum.MVAR);
        assert(
            Il2Cpp.domain
                .assembly("GameAssembly")
                .image.class("Class")
                .method("StaticGenericMethod")
                .generics.map(_ => _.type.enumValue)
        ).is([Il2Cpp.Type.Enum.MVAR, Il2Cpp.Type.Enum.MVAR]);
    });

    test("Il2Cpp.String::content", () => {
        assert(Il2Cpp.string("vfsfitvnm").content).is("vfsfitvnm");
    });

    test("Il2Cpp.String::length", () => {
        assert(Il2Cpp.string("vfsfitvnm").length).is(9);
    });

    test("setting Il2Cpp.String::content", () => {
        const string = Il2Cpp.string("vfsfitvnm");
        string.content = "frida-il2cpp-bridge";

        assert(string.content).is("frida-il2cpp-bridge");
        assert(string.length).is(19);
    });

    test("Il2Cpp.String::object", () => {
        assert(Il2Cpp.string("vfsfitvnm").object.class).is(Il2Cpp.corlib.class("System.String"));
    });

    test("Il2Cpp.Array::get", () => {
        assert(Il2Cpp.array(Il2Cpp.corlib.class("System.Int32"), [0, -1, 12, 3900, -2442, 99]).get(4)).is(-2442);
    });

    test("Il2Cpp.Array::set", () => {
        const array = Il2Cpp.array<number>(Il2Cpp.corlib.class("System.Int32"), [0, -1, 12, 3900, -2442, 99]);
        array.set(4, 2147483647);

        assert(array.get(4)).is(2147483647);
    });

    test("Il2Cpp.Object::base", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("Il2CppObjectTest").nested("BaseTest");
        const instance = T.new();

        assert(instance.method("D").returnType.class).is(T.parent!.type.class);
        assert(instance.class).is(instance.method<Il2Cpp.Object>("D").invoke().class);
        assert(instance.handle).is(instance.method<Il2Cpp.Object>("D").invoke().handle);

        assert(instance.base.class).is(T.parent!.type.class);
        assert(instance.base.base.class).is(T.parent!.parent!.type.class);
        assert(() => instance.base.base.base.class).throws("class System.Object has no parent");
    });

    test("Boxed primiteves are created using the expected types", () => {
        assert(Il2Cpp.boxed(false).class).is(Il2Cpp.corlib.class("System.Boolean"));
        assert(Il2Cpp.boxed(0).class).is(Il2Cpp.corlib.class("System.Int32"));
        assert(Il2Cpp.boxed(NULL).class).is(Il2Cpp.corlib.class("System.IntPtr"));

        assert(Il2Cpp.boxed(0, undefined).class).is(Il2Cpp.corlib.class("System.Int32"));
        assert(Il2Cpp.boxed(0, "int8").class).is(Il2Cpp.corlib.class("System.SByte"));
        assert(Il2Cpp.boxed(0, "int16").class).is(Il2Cpp.corlib.class("System.Int16"));
        assert(Il2Cpp.boxed(0, "int32").class).is(Il2Cpp.corlib.class("System.Int32"));
        assert(Il2Cpp.boxed(0, "int64").class).is(Il2Cpp.corlib.class("System.Int64"));
        assert(Il2Cpp.boxed(0, "uint8").class).is(Il2Cpp.corlib.class("System.Byte"));
        assert(Il2Cpp.boxed(0, "uint16").class).is(Il2Cpp.corlib.class("System.UInt16"));
        assert(Il2Cpp.boxed(0, "uint32").class).is(Il2Cpp.corlib.class("System.UInt32"));
        assert(Il2Cpp.boxed(0, "uint64").class).is(Il2Cpp.corlib.class("System.UInt64"));

        assert(Il2Cpp.boxed(0, "char").class).is(Il2Cpp.corlib.class("System.Char"));

        assert(Il2Cpp.boxed(NULL, undefined).class).is(Il2Cpp.corlib.class("System.IntPtr"));
        assert(Il2Cpp.boxed(NULL, "intptr").class).is(Il2Cpp.corlib.class("System.IntPtr"));
        assert(Il2Cpp.boxed(NULL, "uintptr").class).is(Il2Cpp.corlib.class("System.UIntPtr"));
    });

    test("Boxed primiteves have correct values", () => {
        assert(Il2Cpp.boxed(false).field("m_value").value).is(false);
        assert(Il2Cpp.boxed(true).field("m_value").value).is(true);
        assert(Il2Cpp.boxed(12345).field("m_value").value).is(12345);
        assert(Il2Cpp.boxed(ptr(12345)).field("m_value").value).is(ptr(12345));
    });

    test("Boxed primitives cannot be created if invalid values or types are provided", () => {
        assert(() => Il2Cpp.boxed(0n as any).class).throws("Cannot create boxed primitive using value of type 'bigint'");
        assert(() => Il2Cpp.boxed("something" as any).class).throws("Cannot create boxed primitive using value of type 'string'");

        assert(() => Il2Cpp.boxed(0, "something" as any).class).throws("Unknown primitive type name 'something'");
        assert(() => Il2Cpp.boxed(NULL, "else" as any).class).throws("Unknown primitive type name 'else'");

        assert(() => Il2Cpp.boxed(NULL, "int8" as any).class).throws("expected an integer");
        assert(() => Il2Cpp.boxed(0, "intptr" as any).class).throws("expected a pointer");
    });

    test("Il2Cpp.Object field lookup ignores static fields", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("Il2CppObjectTest").nested("MemberLookupTest");

        assert(T.new().tryField("F")).is(undefined);
        assert(() => T.new().field("F")).throws("couldn't find non-static field F in hierarchy of class Il2CppObjectTest.MemberLookupTest");

        assert(T.new().tryField("H")).not(undefined);
        assert(T.new().tryField("G")?.isStatic).is(false);
    });

    test("Il2Cpp.Object method lookup ignores static methods", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("Il2CppObjectTest");

        assert(T.new().tryMethod("A")).not(undefined);
        assert(T.new().tryMethod("B")).is(undefined);
        assert(T.new().tryMethod("C", 1)).is(undefined);
        assert(T.new().tryMethod("C")).not(undefined);
        assert(T.new().tryMethod("C", 0)).not(undefined);

        assert(T.new().method("A").invoke(NULL)).is(1);
        assert(() => T.new().method("B")).throws("couldn't find non-static method B in hierarchy of class Il2CppObjectTest");

        assert(T.nested("MemberLookupTest").new().tryMethod("C")?.isStatic).is(false);
        assert(T.nested("MemberLookupTest").new().tryMethod("D")?.isStatic).is(false);
    });

    test("Every enum base type matches its 'value__' field type", () => {
        Il2Cpp.domain.assemblies.forEach(_ => {
            _.image.classes
                .filter(_ => _.isEnum)
                .forEach(_ => {
                    assert(_.baseType?.name).is(_.field("value__").type.name);
                });
        });
    });

    test("Structs fields are read correctly", () => {
        const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
        runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));

        assert(runtimeTypeHandle.unbox().field("value").value).is(ptr(0xdeadbeef));
    });

    test("Enums fields are read correctly", () => {
        assert(Il2Cpp.corlib.class("System.DayOfWeek").field<Il2Cpp.ValueType>("Saturday").value.field("value__").value).is(6);
    });

    test("Boxed structs fields are read correctly", () => {
        const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
        runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));

        assert(runtimeTypeHandle.field("value").value).is(ptr(0xdeadbeef));
    });

    test("Boxed structs methods are invoked correctly", () => {
        const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
        runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));

        assert(runtimeTypeHandle.handle.add(runtimeTypeHandle.field("value").offset).readPointer()).is(ptr(0xdeadbeef));
        assert(runtimeTypeHandle.method("get_Value").invoke()).is(ptr(0xdeadbeef));
        assert(Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc().toString()).is("System.RuntimeTypeHandle");
    });

    test("Structs methods are invoked correctly", () => {
        const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc().unbox();
        runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));

        assert(runtimeTypeHandle.method("get_Value").invoke()).is(ptr(0xdeadbeef));
        assert(Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc().toString()).is("System.RuntimeTypeHandle");
    });

    test("Boxing/unboxing structs works correctly", () => {
        const runtimeTypeHandle = Il2Cpp.corlib.class("System.RuntimeTypeHandle").alloc();
        runtimeTypeHandle.method(".ctor").invoke(ptr(0xdeadbeef));

        assert(runtimeTypeHandle.unbox().box().unbox().box().field("value").value).is(ptr(0xdeadbeef));
    });

    test("Boxed enums fields are read correctly", () => {
        assert(Il2Cpp.corlib.class("System.Reflection.MemberTypes").field<Il2Cpp.ValueType>("Constructor").value.box().field("value__").value).is(1);
    });

    test("Il2Cpp.Field::value::get (static)", () => {
        assert(Il2Cpp.corlib.class("System.Type").initialize().field("Delimiter").value).is(46);
        assert(Il2Cpp.domain.assembly("GameAssembly").image.class("Class").initialize().field("enumfield").value.toString()).is("Second");
        assert(Il2Cpp.corlib.class("System.Decimal").initialize().field("MaxValue").value.toString()).is("79228162514264337593543950335");
        assert(Il2Cpp.corlib.class("System.Boolean").initialize().field<Il2Cpp.String>("TrueString").value.content).is("True");
    });

    test("Il2Cpp.Field::value::set (static)", () => {
        const SystemType = Il2Cpp.corlib.class("System.Type").initialize();
        SystemType.field("Delimiter").value = 48;

        assert(SystemType.field("Delimiter").value).is(48);

        {
            const value = SystemType.field("Delimiter").type.class.alloc();
            value.field("m_value").value = 32;
            SystemType.field("Delimiter").value = value;

            assert(SystemType.field("Delimiter").value).is(32);
        }
        {
            const Class = Il2Cpp.domain.assembly("GameAssembly").image.class("Class");
            Class.field("enumfield").value = Class.field("enumfield").type.class.field("Third").value;

            assert(Class.field("enumfield").value.toString()).is("Third");
        }
        {
            const SystemDecimal = Il2Cpp.corlib.class("System.Decimal").initialize();
            const value = SystemDecimal.alloc();
            value.method(".ctor", 1).invoke(123456);
            SystemDecimal.field("MaxValue").value = value;

            assert(SystemDecimal.field("MaxValue").value.toString()).is("123456");
        }
        {
            const SystemBoolean = Il2Cpp.corlib.class("System.Boolean").initialize();
            SystemBoolean.field("TrueString").value = Il2Cpp.string("VeryTrue");

            assert(SystemBoolean.field<Il2Cpp.String>("TrueString").value.content).is("VeryTrue");
        }
    });

    test("Invoke a method that returns an enum value", () => {
        assert(Il2Cpp.corlib.class("System.Environment").method("get_Platform").invoke()?.toString()).is("Unix");
    });

    test("Invoke a method that takes an enum value", () => {
        const DateTimeFormatInfo = Il2Cpp.corlib.class("System.Globalization.DateTimeFormatInfo").initialize();
        const DayOfWeek = Il2Cpp.corlib.class("System.DayOfWeek");

        assert(DateTimeFormatInfo.new().method<Il2Cpp.String>("GetDayName").invoke(DayOfWeek.field("Sunday").value).content).is("Sunday");
    });

    test("References to value types are created correctly", () => {
        const Decimal = Il2Cpp.corlib.class("System.Decimal").initialize();

        const x = Decimal.alloc().unbox();
        const y = Decimal.alloc().unbox();

        x.method(".ctor").overload("System.Int32").invoke(-1234);
        y.method(".ctor").overload("System.Int32").invoke(777);

        const xRef = Il2Cpp.reference(x);

        assert(xRef.handle.add(Decimal.field("lo").offset - Il2Cpp.Object.headerSize).readInt()).is(1234);

        const Compare = Decimal.tryMethod("FCallCompare") ?? Decimal.tryMethod("decimalCompare");

        assert(Compare ? Compare.invoke(xRef, Il2Cpp.reference(y)) : Decimal.method("Sign").invoke(xRef)).is(-1);
    });

    test("Methods are selected by generic parameter count when inflating", () => {
        const Test = Il2Cpp.domain.assembly("GameAssembly").image.class("MethodInflateTest.Parent`1").inflate(Il2Cpp.corlib.class("System.Object"));

        assert(Test.method("A").inflate(Test).invoke()).is(0);
        assert(Test.method("A").inflate(Test, Test).invoke()).is(1);

        assert(Test.method("B").inflate(Test).invoke(NULL)).is(1);
        assert(Test.method("B").inflate(Test, Test).invoke()).is(2);

        assert(Test.method("C").invoke(NULL)).is(0);
        assert(Test.method("C").inflate(Test).invoke(NULL)).is(1);

        assert(() => Test.method("D").inflate(Test)).throws("could not find inflatable signature of method D with 1 generic parameter(s)");
        assert(() => Test.method("C").inflate(Test, Test)).throws("could not find inflatable signature of method C with 2 generic parameter(s)");
    });

    test("Methods are looked up in parent class when inflating", () => {
        const Test = Il2Cpp.domain.assembly("GameAssembly").image.class("MethodInflateTest.Child");

        assert(Test.method("A").inflate(Test).invoke()).is(0);
        assert(Test.method("B").inflate(Test).invoke(NULL)).is(1);

        assert(Test.method("A").inflate(Test, Test, Test).invoke()).is(3);
    });

    test("Overloading selection picks the correct method", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("OverloadTest");

        assert(() => T.new().method("A").overload("A", "B")).throws("couldn't find overloaded method A(A,B)");
        assert(T.new().method("A").overload("OverloadTest.Root").invoke(NULL)).is(0);
        assert(T.new().method("A").overload("OverloadTest.Child1").invoke(NULL)).is(1);
        assert(T.new().method("A").tryOverload("OverloadTest.Child11")).is(undefined);
        assert(T.new().method("A").tryOverload("OverloadTest.Child2")).is(undefined);
        assert(T.new().method("A").overload("OverloadTest.Child3").invoke(NULL)).is(2);
        assert(T.new().method("A").overload("OverloadTest.Child4<OverloadTest.Root>").invoke(NULL)).is(4);
        assert(T.new().method("A").tryOverload("OverloadTest.Child4<T>")).is(undefined);
        assert(T.new().method("A").tryOverload("OverloadTest.Child4<OverloadTest.Child1>")).is(undefined);
    });

    test("Overloading selection looks in parent class", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("OverloadTest").nested("Nested");

        assert(T.new().method("C").overload().invoke()).is(2);
        assert(T.new().method("C").overload("System.Int32").invoke(-1)).is(-1);
    });

    test("Overloading selection by type picks the most precise method possible", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("OverloadTest");

        assert(T.new().method("A").overload(T.nested("Root")).invoke(NULL)).is(0);
        assert(T.new().method("A").overload(T.nested("Child1")).invoke(NULL)).is(1);
        assert(T.new().method("A").overload(T.nested("Child11")).invoke(NULL)).is(1);
        assert(T.new().method("A").overload(T.nested("Child2")).invoke(NULL)).is(0);
        assert(T.new().method("A").overload(T.nested("Child3")).invoke(NULL)).is(2);
        assert(T.nested("Nested").new().method("A").overload(T.nested("Child2")).invoke(NULL)).is(3);
        assert(T.nested("Nested").new().method("A").overload(T.nested("Child3")).invoke(NULL)).is(2);
        assert(T.nested("Nested").new().method("A").overload(T.nested("Child311")).invoke(NULL)).is(2);

        assert(T.method("E").overload(T.nested("Child1"), T.nested("Child11")).invoke(NULL, NULL)).is(1);
        assert(T.method("E").overload(T.nested("Child11"), T.nested("Child1")).invoke(NULL, NULL)).is(ANY);
        assert(T.method("E").overload(T.nested("Child11"), T.nested("Child11")).invoke(NULL, NULL)).is(ANY);
        assert(T.method("E").tryOverload(T.nested("Child1"), T.nested("Root"))).is(undefined);
    });

    test("Overloading instance methods do not select static methods", () => {
        const T = Il2Cpp.domain.assembly("GameAssembly").image.class("OverloadTest");

        assert(T.method("D").tryOverload("OverloadTest.Child1")).not(undefined);
        assert(T.new().method("D").tryOverload("OverloadTest.Child1")).is(undefined);
        assert(T.method("D").tryOverload("OverloadTest.Rooat")).is(undefined);
        assert(T.new().method("D").tryOverload("OverloadTest.Rot")).is(undefined);
        assert(T.method("D").overload("OverloadTest.Root").isStatic).is(false);
        assert(() => T.method("D").overload("OverloadTest.Rooat")).throws("couldn't find overloaded method D(OverloadTest.Rooat)");
        assert(() => T.new().method("D").overload("OverloadTest.Rot")).throws("couldn't find overloaded method D(OverloadTest.Rot)");
    });

    test("Il2Cpp.Method::fromVirtualAddress", () => {
        Il2Cpp.domain.assembly("GameAssembly").image.classes.forEach(_ => {
            _.methods
                .filter(_ => !_.virtualAddress.isNull())
                .forEach(_ => {
                    assert(Il2Cpp.Method.fromVirtualAddress(_.virtualAddress)).is(_);
                });
        });
    });
}).then(() => send({ action: "stop" }));
