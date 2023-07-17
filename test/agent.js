/// <reference path="../dist/index.d.ts" />

Il2Cpp.perform(() => {
    test("Il2Cpp::unityVersion to be correct", $EXPECTED_UNITY_VERSION, () => {
        return Il2Cpp.unityVersion;
    });

    test("Il2Cpp::currentThread to be not null", true, () => {
        return Il2Cpp.currentThread != null;
    });

    test("Il2Cpp.Thread::id to be correct", Process.getCurrentThreadId(), () => {
        return Il2Cpp.currentThread?.id;
    });

    test("Il2Cpp.Domain::object class handle to be correct", Il2Cpp.corlib.class("System.AppDomain").handle, () => {
        return Il2Cpp.domain.object.class.handle;
    });

    test("Il2Cpp.Domain::assemblies to be non-empty", true, () => {
        return Il2Cpp.domain.assemblies.length > 0;
    });

    test("Il2Cpp.String::content to be correct", "vfsfitvnm", () => {
        return Il2Cpp.string("vfsfitvnm").content;
    });

    test("Il2Cpp.String::length to be correct", 9, () => {
        return Il2Cpp.string("vfsfitvnm").length;
    });

    test("Il2Cpp.String::content to be editable", "frida-il2cpp-bridge", () => {
        const string = Il2Cpp.string("vfsfitvnm");
        string.content = "frida-il2cpp-bridge";
        return string.content;
    });

    test("Il2Cpp.String::length to be editable", 19, () => {
        const string = Il2Cpp.string("vfsfitvnm");
        string.content = "frida-il2cpp-bridge";
        return string.length;
    });

    test("Il2Cpp.String::object class handle to be correct", Il2Cpp.corlib.class("System.String").handle, () => {
        return Il2Cpp.string("vfsfitvnm").object.class.handle;
    });

    test("Il2Cpp.Array::get to be correct", -2442, () => {
        const SystemInt32 = Il2Cpp.corlib.class("System.Int32");
        return Il2Cpp.array(SystemInt32, [0, -1, 12, 3900, -2442, 99]).get(4);
    });

    test("Il2Cpp.Array::set to be correct", 2147483647, () => {
        const SystemInt32 = Il2Cpp.corlib.class("System.Int32");
        const array = Il2Cpp.array(SystemInt32, [0, -1, 12, 3900, -2442, 99]);
        array.set(4, 2147483647);
        return array.get(4);
    });

    send("done");
});

function test(title, expected, getActual) {
    try {
        const time = +new Date();
        const actual = getActual();
        const duration = +new Date() - time;

        send({
            title: title,
            actual: actual,
            expected: expected,
            duration: duration
        });
    } catch (error) {
        send({
            title: title,
            error: error.message.replace("\x1B[0m", "")
        });
    }
}
