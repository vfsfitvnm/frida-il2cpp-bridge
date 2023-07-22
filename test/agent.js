Il2Cpp.perform(() => {
    send(`\x1b[94m\x1b[1m►\x1b[22m\x1b[0m ${$EXPECTED_UNITY_VERSION}`);

    test("Il2Cpp::unityVersion to be correct", () => {
        assert($EXPECTED_UNITY_VERSION, Il2Cpp.unityVersion);
    });

    test("Il2Cpp::currentThread to be not null", () => {
        assert(false, Il2Cpp.currentThread == null);
    });

    test("Il2Cpp.Thread::id to be correct", () => {
        assert(Process.getCurrentThreadId(), Il2Cpp.currentThread?.id);
    });

    test("Il2Cpp.Domain::object class handle to be correct", () => {
        assert(Il2Cpp.corlib.class("System.AppDomain").handle, Il2Cpp.domain.object.class.handle);
    });

    test("Il2Cpp.Domain::assemblies to be non-empty", () => {
        assert(true, Il2Cpp.domain.assemblies.length > 0);
    });

    test("Il2Cpp.String::content to be correct", () => {
        assert("vfsfitvnm", Il2Cpp.string("vfsfitvnm").content);
    });

    test("Il2Cpp.String::length to be correct", () => {
        assert(9, Il2Cpp.string("vfsfitvnm").length);
    });

    test("Il2Cpp.String::content to be editable", () => {
        const string = Il2Cpp.string("vfsfitvnm");
        string.content = "frida-il2cpp-bridge";

        assert("frida-il2cpp-bridge", string.content);
        assert(19, string.length);
    });

    test("Il2Cpp.String::object class handle to be correct", () => {
        assert(Il2Cpp.corlib.class("System.String").handle, Il2Cpp.string("vfsfitvnm").object.class.handle);
    });

    test("Il2Cpp.Array::get to be correct", () => {
        const SystemInt32 = Il2Cpp.corlib.class("System.Int32");
        const array = Il2Cpp.array(SystemInt32, [0, -1, 12, 3900, -2442, 99]);

        assert(-2442, array.get(4));
    });

    test("Il2Cpp.Array::set to be correct", () => {
        const SystemInt32 = Il2Cpp.corlib.class("System.Int32");
        const array = Il2Cpp.array(SystemInt32, [0, -1, 12, 3900, -2442, 99]);
        array.set(4, 2147483647);

        assert(2147483647, array.get(4));
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

function assert(expected, actual) {
    const areEquals = expected instanceof NativePointer ? expected.equals(actual) : expected == actual;

    if (!areEquals) {
        throw new Error(`\x1b[1m${expected}\x1b[22m was expected, but got \x1b[1m${actual}\x1b[22m`);
    }
}
