namespace Il2Cpp {
    export class GCHandle {
        /** @internal */
        constructor(readonly handle: number) {}

        /** Gets the object associated to this handle. */
        get target(): Il2Cpp.Object | null {
            const handle = Il2Cpp.Api.gcHandleGetTarget(this.handle);
            return handle.isNull() ? null : new Il2Cpp.Object(handle);
        }

        /** Frees this handle. */
        free(): void {
            return Il2Cpp.Api.gcHandleFree(this.handle);
        }
    }
}
