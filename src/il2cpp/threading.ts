namespace Il2Cpp {
    /** Gets the attached threads. */
    export declare const attachedThreads: Il2Cpp.Thread[];
    getter(Il2Cpp, "attachedThreads", () => {
        if (Il2Cpp.currentThread == null) {
            raise("only Il2Cpp threads can invoke Il2Cpp.attachedThreads");
        }

        return readNativeList(Il2Cpp.Api.threadGetAllAttachedThreads).map(_ => new Il2Cpp.Thread(_));
    });

    /** Gets the current attached thread, if any. */
    export declare const currentThread: Il2Cpp.Thread | null;
    getter(Il2Cpp, "currentThread", () => {
        const handle = Il2Cpp.Api.threadCurrent();
        return handle.isNull() ? null : new Il2Cpp.Thread(handle);
    });

    /** Gets the current attached thread, if any. */
    export declare const mainThread: Il2Cpp.Thread;
    getter(Il2Cpp, "mainThread", () => {
        // I'm not sure if this is always the case. Alternatively, we could pick the thread
        // with the lowest managed id, but I'm not sure that always holds true, either.
        return attachedThreads[0];
    });
}
