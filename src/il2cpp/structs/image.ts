import { cache } from "decorator-cache-getter";
import { NonNullNativeStruct } from "../../utils/native-struct";
import { cacheInstances, memoize } from "../../utils/utils";
import { levenshtein } from "../decorators";

/** Represents a `Il2CppImage`. */
@cacheInstances
class Il2CppImage extends NonNullNativeStruct {
    /** Gets the COR library. */
    @cache
    static get corlib(): Il2Cpp.Image {
        return new Il2Cpp.Image(Il2Cpp.Api._getCorlib());
    }

    /** Gets the assembly in which the current image is defined. */
    @cache
    get assembly(): Il2Cpp.Assembly {
        return new Il2Cpp.Assembly(Il2Cpp.Api._imageGetAssembly(this));
    }

    /** Gets the amount of classes defined in this image. */
    @cache
    get classCount(): number {
        return Il2Cpp.Api._imageGetClassCount(this);
    }

    /** Gets the classes defined in this image. */
    @cache
    get classes(): Il2Cpp.Class[] {
        if (Unity.isBelow2018_3_0) {
            const types = this.assembly.object.method<Il2Cpp.Array<Il2Cpp.Object>>("GetTypes").invoke(false);
            // On Unity 5.3.8f1, getting System.Reflection.Emit.OpCodes type name
            // without iterating all the classes first somehow blows things up at
            // app startup, hence the `Array.from`.
            return Array.from(types).map(e => new Il2Cpp.Class(Il2Cpp.Api._classFromSystemType(e)));
        } else {
            return Array.from(Array(this.classCount), (_, i) => new Il2Cpp.Class(Il2Cpp.Api._imageGetClass(this, i)));
        }
    }

    /** Gets the name of this image. */
    @cache
    get name(): string {
        return Il2Cpp.Api._imageGetName(this).readUtf8String()!;
    }

    /** Gets the class with the specified name defined in this image. */
    @levenshtein("classes", e => e.type.name)
    class(name: string): Il2Cpp.Class {
        return this.tryClass(name)!;
    }

    /** Gets the class with the specified name defined in this image. */
    @memoize
    tryClass(name: string): Il2Cpp.Class | null {
        const dotIndex = name.lastIndexOf(".");
        const classNamespace = Memory.allocUtf8String(dotIndex == -1 ? "" : name.slice(0, dotIndex));
        const className = Memory.allocUtf8String(name.slice(dotIndex + 1));

        const handle = Il2Cpp.Api._classFromName(this, classNamespace, className);
        return handle.isNull() ? null : new Il2Cpp.Class(handle);
    }
}

Il2Cpp.Image = Il2CppImage;

declare global {
    namespace Il2Cpp {
        class Image extends Il2CppImage {}
    }
}
