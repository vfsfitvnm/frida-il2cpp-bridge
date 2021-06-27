import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { NativeStructNotNull } from "../../utils/native-struct";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("Assembly")
class Il2CppAssembly extends NativeStructNotNull {
    @cache
    get image(): Il2Cpp.Image {
        return new Il2Cpp.Image(Api._assemblyGetImage(this.handle));
    }

    @cache
    get name(): string {
        if (Il2Cpp.unityVersion.isLegacy) {
            return this.image.name.replace(".dll", "");
        } else {
            return Api._assemblyGetName(this.handle)!;
        }
    }
}
