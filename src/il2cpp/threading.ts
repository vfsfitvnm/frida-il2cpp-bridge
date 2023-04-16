namespace Il2Cpp {
    /** Gets the attached threads. */
    export declare const attachedThreads: Il2Cpp.Thread[];
    getter(Il2Cpp, "attachedThreads", () => {
        if (Il2Cpp.currentThread == null) {
            raise("only Il2Cpp threads can invoke Il2Cpp.attachedThreads");
        }

        return readNativeList(Il2Cpp.Api._threadGetAllAttachedThreads).map(_ => new Il2Cpp.Thread(_));
    });

    /** Gets the current attached thread, if any. */
    export declare const currentThread: Il2Cpp.Thread | null;
    getter(Il2Cpp, "currentThread", () => {
        const handle = Il2Cpp.Api._threadCurrent();
        return handle.isNull() ? null : new Il2Cpp.Thread(handle);
    });

    /** Schedules a callback on the Il2Cpp initializer thread. */
    export function scheduleOnInitializerThread<T>(block: () => T | Promise<T>): Promise<T> {
        const maybeInitializerThread = Il2Cpp.attachedThreads[0];

        return new Promise<T>(resolve => {
            const listener = Interceptor.attach(Il2Cpp.Api._threadCurrent, () => {
                if (Il2Cpp.Api._threadCurrent().equals(maybeInitializerThread)) {
                    listener.detach();
                    const result = block();
                    setImmediate(() => resolve(result));
                }
            });
        });
    }
}
