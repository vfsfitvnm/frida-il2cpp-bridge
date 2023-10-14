namespace Il2Cpp {
    export class GCHandle {
        /** @internal */
        constructor(readonly handle: number) {}

        /** Gets the object associated to this handle. */
        get target(): Il2Cpp.Object | null {
            return new Il2Cpp.Object(Il2Cpp.api.gcHandleGetTarget(this.handle)).asNullable();
        }

        /** Frees this handle. */
        free(): void {
            return Il2Cpp.api.gcHandleFree(this.handle);
        }
    }
}
