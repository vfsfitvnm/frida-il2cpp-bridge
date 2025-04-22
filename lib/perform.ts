namespace Il2Cpp {
    /** Attaches the caller thread to Il2Cpp domain and executes the given block.  */
    export async function perform<T>(block: () => T | Promise<T>, flag: "free" | "bind" | "leak" | "main" = "bind"): Promise<T> {
        let attachedThread: Il2Cpp.Thread | null = null;
        try {
            const isInMainThread = await initialize(flag == "main");

            if (flag == "main" && !isInMainThread) {
                return perform(() => Il2Cpp.mainThread.schedule(block), "free");
            }

            if (Il2Cpp.currentThread == null) {
                attachedThread = Il2Cpp.domain.attach();
            }

            if (flag == "bind" && attachedThread != null) {
                Script.bindWeak(globalThis, () => attachedThread?.detach());
            }

            const result = block();

            return result instanceof Promise ? await result : result;
        } catch (error: any) {
            Script.nextTick(_ => { throw _; }, error); // prettier-ignore
            return Promise.reject<T>(error);
        } finally {
            if (flag == "free" && attachedThread != null) {
                attachedThread.detach();
            }
        }
    }
}
