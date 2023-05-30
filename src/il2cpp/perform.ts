namespace Il2Cpp {
    /** Attaches the caller thread to Il2Cpp domain and executes the given block.  */
    export async function perform<T>(block: () => T | Promise<T>, flag: "free" | "bind" | "leak" | "main" = "bind"): Promise<T> {
        try {
            const isInMainThread = await initialize(flag == "main");

            if (flag == "main" && !isInMainThread) {
                return perform(() => Il2Cpp.mainThread.schedule(block), "free");
            }

            let thread = Il2Cpp.currentThread;
            const isForeignThread = thread == null;
            thread || (thread = Il2Cpp.domain.attach());

            const result = block();

            if (isForeignThread) {
                if (flag == "free") {
                    thread.detach();
                } else if (flag == "bind") {
                    Script.bindWeak(globalThis, () => thread!.detach());
                }
            }

            return result instanceof Promise ? await result : result;
        } catch (error: any) {
            Script.nextTick(_ => { throw _; }, error); // prettier-ignore
            return Promise.reject<T>(error);
        }
    }
}
