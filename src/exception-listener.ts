namespace Il2Cpp {
    /**
     * Installs a listener to track any thrown (unrecoverable) C# exception. \
     * This may be useful when incurring in `abort was called` errors.
     *
     * By default, it only tracks exceptions that were thrown by the *caller*
     * thread.
     *
     * **It may not work for every platform.**
     *
     * ```ts
     * Il2Cpp.perform(() => {
     *     Il2Cpp.installExceptionListener("all");
     *
     *     // rest of the code
     * });
     * ```
     *
     * For instance, it may print something along:
     * ```
     * System.NullReferenceException: Object reference not set to an instance of an object.
     *   at AddressableLoadWrapper+<LoadGameObject>d__3[T].MoveNext () [0x00000] in <00000000000000000000000000000000>:0
     *   at UnityEngine.SetupCoroutine.InvokeMoveNext (System.Collections.IEnumerator enumerator, System.IntPtr returnValueAddress) [0x00000] in <00000000000000000000000000000000>:0
     * ```
     */
    export function installExceptionListener(targetThread: "current" | "all" = "current"): InvocationListener {
        const currentThread = Il2Cpp.api.threadGetCurrent();

        return Interceptor.attach(Il2Cpp.module.getExportByName("__cxa_throw"), function (args) {
            if (targetThread == "current" && !Il2Cpp.api.threadGetCurrent().equals(currentThread)) {
                return;
            }

            inform(new Il2Cpp.Object(args[0].readPointer()));
        });
    }
}
