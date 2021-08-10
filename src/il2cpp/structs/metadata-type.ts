import { cache } from "decorator-cache-getter";

import { NonNullNativeStruct } from "../../utils/native-struct";

/** Represents a `Il2CppMetadataType`. */
class Il2CppMetadataType extends NonNullNativeStruct {
    /** */
    @cache
    get assemblyName(): string {
        return Il2Cpp.Api._metadataTypeGetAssemblyName(this).readUtf8String()!;
    }

    /** */
    @cache
    get baseOrElementTypeIndex(): number {
        return Il2Cpp.Api._metadataTypeGetBaseOrElementTypeIndex(this);
    }

    /** */
    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._metadataTypeGetClass(this));
    }

    /** */
    @cache
    get name(): string {
        return Il2Cpp.Api._metadataTypeGetName(this).readUtf8String()!;
    }
}

Il2Cpp.MetadataType = Il2CppMetadataType;

declare global {
    namespace Il2Cpp {
        class MetadataType extends Il2CppMetadataType {}
    }
}
