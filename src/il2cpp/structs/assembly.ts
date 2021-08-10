import { cache } from "decorator-cache-getter";

import { NonNullNativeStruct } from "../../utils/native-struct";

/** Represents a `Il2CppAssembly`. */
class Il2CppAssembly extends NonNullNativeStruct {
    /** Gets the image of this assembly. */
    @cache
    get image(): Il2Cpp.Image {
        return new Il2Cpp.Image(Il2Cpp.Api._assemblyGetImage(this));
    }

    /** Gets the name of this assembly. */
    @cache
    get name(): string {
        if (Il2Cpp.unityVersion.isBefore2018_3_0) {
            return this.image.name.replace(".dll", "");
        } else {
            return Il2Cpp.Api._assemblyGetName(this).readUtf8String()!;
        }
    }
}

Il2Cpp.Assembly = Il2CppAssembly;

declare global {
    namespace Il2Cpp {
        class Assembly extends Il2CppAssembly {}
    }
}
