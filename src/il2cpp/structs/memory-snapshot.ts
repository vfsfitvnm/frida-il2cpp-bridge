import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NativeStructNotNull } from "../../utils/native-struct";

@injectToIl2Cpp("MemorySnapshot")
class Il2CppMemorySnapshot extends NativeStructNotNull {
    readonly weakRefId: WeakRefId;

    constructor() {
        super(Api._memorySnapshotCapture());
        this.weakRefId = Script.bindWeak(this, Api._memorySnapshotFree.bind(this, this.handle));
    }

    @cache
    get objects(): Il2Cpp.Object[] {
        const objects: Il2Cpp.Object[] = [];

        const count = this.trackedObjectCount.toNumber();
        const start = this.objectsPointer;

        for (let i = 0; i < count; i++) {
            objects.push(new Il2Cpp.Object(start.add(i * Process.pointerSize).readPointer()));
        }

        return objects;
    }

    @cache
    get objectsPointer(): NativePointer {
        return Api._memorySnapshotGetObjects(this.handle);
    }

    @cache
    get trackedObjectCount(): UInt64 {
        return Api._memorySnapshotGetTrackedObjectCount(this.handle);
    }

    free(): void {
        Script.unbindWeak(this.weakRefId);
    }
}
