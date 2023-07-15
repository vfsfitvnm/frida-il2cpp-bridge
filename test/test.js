/// <reference path="../dist/index.d.ts" />

Il2Cpp.perform(() => {
    test("Il2Cpp.unityVersion to be correct", $EXPECTED_UNITY_VERSION, () => {
        return Il2Cpp.unityVersion;
    });

    test("Il2Cpp.currentThread to be not null", true, () => {
        return Il2Cpp.currentThread != null;
    });

    test("Il2Cpp.currentThread.id to be correct", Process.getCurrentThreadId(), () => {
        return Il2Cpp.currentThread?.id;
    });

    test("Il2Cpp.domain.name to be correct", "IL2CPP ROOT DOMAIN", () => {
        return Il2Cpp.domain.object.method("getFriendlyName").invoke().content;
    });

    test("Il2Cpp.domain.assemblies to be non-empty", true, () => {
        return Il2Cpp.domain.assemblies.length > 0;
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
            error: error.message
        });
    }
}
