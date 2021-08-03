import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NonNullNativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("MetadataSnapshot")
class Il2CppMetadataSnapshot extends NonNullNativeStruct {
    @cache
    get metadataTypeCount(): number {
        return Api._metadataSnapshotGetMetadataTypeCount(this);
    }

    @cache
    get metadataTypes(): Readonly<Record<string, Il2Cpp.MetadataType>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.MetadataType> = {};

        let handle: NativePointer;

        while (!(handle = Api._metadataSnapshotGetMetadataTypes(this, iterator)).isNull()) {
            const metadataType = new Il2Cpp.MetadataType(handle);
            record[metadataType.name] = metadataType;
        }

        return record;
    }
}
