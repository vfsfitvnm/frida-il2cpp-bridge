import { getOrNull } from "../../utils/utils";

/** Represents a GCHandle. */
class Il2CppGCHandle {
    /** @internal */
    constructor(readonly handle: number) {}

    /** Gets the object associated to this handle. */
    get target(): Il2Cpp.Object | null {
        return getOrNull(Il2Cpp.Api._gcHandleGetTarget(this.handle), Il2Cpp.Object);
    }

    /** Frees this handle. */
    free(): void {
        return Il2Cpp.Api._gcHandleFree(this.handle);
    }
}

Il2Cpp.GC.Handle = Il2CppGCHandle;

declare global {
    namespace Il2Cpp {
        namespace GC {
            class Handle extends Il2CppGCHandle {}
        }
    }
}
