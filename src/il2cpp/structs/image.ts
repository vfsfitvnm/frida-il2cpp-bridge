import { cache } from "decorator-cache-getter";
import { NonNullNativeStruct } from "../../utils/native-struct";
import { addLevenshtein, getOrNull, IterableRecord, makeIterable } from "../../utils/utils";

/** Represents a `Il2CppImage`. */
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
    get classes(): IterableRecord<Il2Cpp.Class> {
        const record: Record<string, Il2Cpp.Class> = {};

        if (Unity.isBelow2018_3_0) {
            let object = this.assembly.object;
            while (!("GetTypes" in object.methods)) object = object.base;

            const types = object.methods.GetTypes.invoke<Il2Cpp.Array<Il2Cpp.Object>>(false);

            for (const type of types) {
                const klass = new Il2Cpp.Class(Il2Cpp.Api._classFromSystemType(type));
                record[klass.type.name] = klass;
            }
        } else {
            const end = this.classCount;

            for (let i = 0; i < end; i++) {
                const klass = new Il2Cpp.Class(Il2Cpp.Api._imageGetClass(this, i));
                record[klass.type.name] = klass;
            }
        }

        return makeIterable(addLevenshtein(record));
    }

    /** Gets the name of this image. */
    @cache
    get name(): string {
        return Il2Cpp.Api._imageGetName(this).readUtf8String()!;
    }

    /** Gets the class with the specified namespace and name defined in this image. */
    getClass(namespace: string, name: string): Il2Cpp.Class | null {
        return getOrNull(Il2Cpp.Api._classFromName(this, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name)), Il2Cpp.Class);
    }
}

Il2Cpp.Image = Il2CppImage;

declare global {
    namespace Il2Cpp {
        class Image extends Il2CppImage {}
    }
}
