import { injectToIl2Cpp } from "../decorators";
import { NativeStruct, NonNullNativeStruct } from "../../utils/native-struct";
import { cache } from "decorator-cache-getter";
import { Api } from "../api";

@injectToIl2Cpp("MetadataSnapshot")
class Il2CppMetadataSnapshot extends NonNullNativeStruct {
    @cache
    get metadataTypeCount(): number {
        return Api._metadataSnapshotGetMetadataTypeCount(this);
    }

    @cache
    get metadataTypes(): Il2Cpp.MetadataType[] {
        const iterator = Memory.alloc(Process.pointerSize);
        const array: Il2Cpp.MetadataType[] = [];

        let handle: NativePointer;

        while (!(handle = Api._metadataSnapshotGetMetadataTypes(this, iterator)).isNull()) {
            array.push(new Il2Cpp.MetadataType(handle));
        }

        return array;
    }
}
