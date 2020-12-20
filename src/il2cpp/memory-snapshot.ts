import Api from "./api";
import { lazy } from "../utils/decorators";
import { raise } from "../utils/console";

/** @internal */
export default class Il2CppMemorySnapshot {
    private isFreed = false;

    private constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get trackedObjectCount() {
        return this.isFreed ? -1 : Api._memorySnapshotGetTrackedObjectCount(this.handle).toNumber();
    }

    @lazy get objectsPointer() {
        return this.isFreed ? NULL : Api._memorySnapshotGetObjects(this.handle);
    }

    static capture() {
        return new Il2CppMemorySnapshot(Api._memorySnapshotCapture());
    }

    free() {
        this.isFreed = true;
        Api._memorySnapshotFree(this.handle);
    }
}
