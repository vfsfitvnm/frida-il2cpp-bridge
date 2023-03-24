import { cache } from "decorator-cache-getter";
import { NonNullNativeStruct } from "../../utils/native-struct.js";
import { cacheInstances } from "../../utils/utils.js";

/** Represents a `Il2CppAssembly`. */
@cacheInstances
class Il2CppAssembly extends NonNullNativeStruct {
    /** Gets the image of this assembly. */
    @cache
    get image(): Il2Cpp.Image {
        return new Il2Cpp.Image(Il2Cpp.Api._assemblyGetImage(this));
    }

    /** Gets the name of this assembly. */
    @cache
    get name(): string {
        return this.image.name.replace(".dll", "");
    }

    /** Gets the encompassing object of the current assembly. */
    @cache
    get object(): Il2Cpp.Object {
        return Il2Cpp.Image.corlib.class("System.Reflection.Assembly").method<Il2Cpp.Object>("Load").invoke(Il2Cpp.String.from(this.name));
    }
}

Il2Cpp.Assembly = Il2CppAssembly;

declare global {
    namespace Il2Cpp {
        class Assembly extends Il2CppAssembly {}
    }
}
