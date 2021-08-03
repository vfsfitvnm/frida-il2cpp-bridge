import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NonNullNativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("MetadataType")
class Il2CppMetadataType extends NonNullNativeStruct {
    @cache
    get assemblyName(): string {
        return Api._metadataTypeGetAssemblyName(this).readUtf8String()!;
    }

    @cache
    get baseOrElementTypeIndex(): number {
        return Api._metadataTypeGetBaseOrElementTypeIndex(this);
    }

    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._metadataTypeGetClass(this));
    }

    @cache
    get name(): string {
        return Api._metadataTypeGetName(this).readUtf8String()!;
    }
}
