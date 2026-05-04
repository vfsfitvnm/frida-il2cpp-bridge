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
        const currentThread = Il2Cpp.exports.threadGetCurrent();

        const is64Bit = Process.pointerSize === 8;
        if (Process.platform === 'windows') return Interceptor.attach(Module.findGlobalExportByName("RaiseException"), {
            onEnter(args) {
                if (targetThread === "current" &&
                    !Il2Cpp.exports.threadGetCurrent().equals(currentThread)) {
                    return;
                }
    
                const exceptionCode = args[0].toUInt32();
                if (exceptionCode !== 0xE06D7363) {
                    return;
                }
    
                const nArgs = args[2].toInt32();
                const lpParams = args[3];
    
                const expectedArgs = is64Bit ? 4 : 3;
                if (nArgs < expectedArgs || lpParams.isNull()) {
                    return;
                }
    
                try {
                    const ptrSize = Process.pointerSize;
                    const pExceptionObject = lpParams.add(ptrSize * 8).readPointer();
                    const throwInfoOffset = is64Bit ? 16 : 8;
                    const pThrowInfo = lpParams.add(throwInfoOffset).readPointer();
    
                    inform("\n=== C++ Exception Caught ===");
                    inform(`Exception Object: ${pExceptionObject}`);
                    inform(`ThrowInfo: ${pThrowInfo}`);
                    if (!pExceptionObject.isNull()) {
                        const exceptionObj = new Il2Cpp.Object(pExceptionObject);
                        inform(exceptionObj);
                    }
                } catch (e) {
                    inform(`Error parsing exception: ${e.message}`);
                }
            }
        });
        
        return Interceptor.attach(Il2Cpp.module.getExportByName("__cxa_throw"), function (args) {
            if (targetThread == "current" && !Il2Cpp.exports.threadGetCurrent().equals(currentThread)) {
                return;
            }

            inform(new Il2Cpp.Object(args[0].readPointer()));
        });
    }
}
