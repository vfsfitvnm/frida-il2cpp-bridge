import { Api } from "../api";

import { _Il2CppObject } from "./object";

/**
 * Represents a GCHandle.
 */
export class _Il2CppGCHandle {

    /** @internal */
    constructor(readonly handle: number) {}

    /**
     * Return the object associated to the handle.
     */
    get target(): _Il2CppObject  {
        return new _Il2CppObject(Api._gcHandleGetTarget(this.handle));
    }

    /**
     * Frees the handle.
     */
    free(): void {
        return Api._gcHandleFree(this.handle);
    }
}