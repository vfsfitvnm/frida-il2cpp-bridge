namespace Il2Cpp {
    /** Attaches the caller thread to Il2Cpp domain and executes the given block.  */
    export async function perform<T>(block: () => T | Promise<T>, detach: "always" | "lazy" | "never" = "lazy"): Promise<T> {
        await initialize();

        let thread = Il2Cpp.currentThread;
        const isForeignThread = thread == null;
        thread ??= Il2Cpp.domain.attach();

        try {
            const result = block();
            return result instanceof Promise ? await result : result;
        } catch (error: any) {
            Script.nextTick(_ => { throw _; }, error); // prettier-ignore
            return Promise.reject<T>(error);
        } finally {
            if (isForeignThread) {
                switch (detach) {
                    case "lazy":
                        Script.bindWeak(globalThis, () => thread?.detach());
                        break;
                    case "never":
                        break;
                    case "always":
                    default:
                        thread.detach();
                        break;
                }
            }
        }
    }
}
