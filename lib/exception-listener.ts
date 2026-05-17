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
        let target: NativePointer;
        let impl: (this: InvocationContext, args: InvocationArguments) => Il2Cpp.Object | undefined;

        switch (Process.platform) {
            case "windows":
                // On Windows, _CxxThrowException
                // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raiseexception
                //
                // VOID RaiseException(
                // [in] DWORD           dwExceptionCode,
                // [in] DWORD           dwExceptionFlags,
                // [in] DWORD           nNumberOfArguments,
                // [in] const ULONG_PTR *lpArguments
                // );
                target = Module.getGlobalExportByName("RaiseException");
                impl = function (args) {
                    // Visual C++ compiler uses the following code for C++ exceptions
                    if (args[0].toUInt32() != 0xe06d7363) {
                        return;
                    }

                    const nArgs = args[2].toInt32();
                    const lpParams = args[3];

                    const expectedArgs = Process.pointerSize == 8 ? 4 : 3;
                    if (nArgs < expectedArgs || lpParams.isNull()) {
                        return;
                    }

                    return new Il2Cpp.Object(lpParams.add(Process.pointerSize * 8).readPointer());
                };
            default:
                target = Il2Cpp.module.getExportByName("__cxa_throw");
                impl = function (args) {
                    return new Il2Cpp.Object(args[0].readPointer());
                };
        }

        const currentThread = Il2Cpp.exports.threadGetCurrent();

        return Interceptor.attach(target, function (args) {
            if (targetThread == "current" && !Il2Cpp.exports.threadGetCurrent().equals(currentThread)) {
                return;
            }

            const exceptionObject = impl.bind(this)(args);
            if (exceptionObject?.asNullable() != undefined) {
                inform(exceptionObject);
            }
        });
    }
}
