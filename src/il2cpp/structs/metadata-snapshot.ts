import { cache } from "decorator-cache-getter";

import { NonNullNativeStruct } from "../../utils/native-struct";
import { addLevenshtein, makeIterable } from "../../utils/utils";

/** Represents a `Il2CppMetadataSnapshot`. */
class Il2CppMetadataSnapshot extends NonNullNativeStruct {
    /** */
    @cache
    get metadataTypeCount(): number {
        return Il2Cpp.Api._metadataSnapshotGetMetadataTypeCount(this);
    }

    /** */
    @cache
    get metadataTypes(): IterableRecord<Il2Cpp.MetadataType> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.MetadataType> = {};

        let handle: NativePointer;

        while (!(handle = Il2Cpp.Api._metadataSnapshotGetMetadataTypes(this, iterator)).isNull()) {
            const metadataType = new Il2Cpp.MetadataType(handle);
            record[metadataType.name] = metadataType;
        }

        return makeIterable(addLevenshtein(record));
    }
}

Il2Cpp.MetadataSnapshot = Il2CppMetadataSnapshot;

declare global {
    namespace Il2Cpp {
        class MetadataSnapshot extends Il2CppMetadataSnapshot {}
    }
}
