import { cache } from "decorator-cache-getter";

import { since } from "../decorators";

import { NonNullNativeStruct } from "../../utils/native-struct";
import { addLevenshtein, getOrNull } from "../../utils/utils";

/** Represents a `Il2CppImage`. */
class Il2CppImage extends NonNullNativeStruct {
    /** Gets the COR library. */
    static get corlib(): Il2Cpp.Image {
        return new Il2Cpp.Image(Il2Cpp.Api._getCorlib());
    }

    /** Gets the assembly in which the current image is defined. */
    @cache
    @since("2018.1.0")
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
    get classes(): Readonly<Record<string, Il2Cpp.Class>> {
        const record: Record<string, Il2Cpp.Class> = {};

        if (Il2Cpp.unityVersion.isBefore2018_3_0) {
            const start = this.classStart;
            const end = start + this.classCount;

            const globalIndex = Memory.alloc(Process.pointerSize);
            globalIndex.add(Il2Cpp.Type.offsetOfTypeEnum).writeInt(0x20);

            for (let i = start; i < end; i++) {
                const klass = new Il2Cpp.Class(Il2Cpp.Api._typeGetClassOrElementClass(globalIndex.writeInt(i)));
                record[klass.type!.name!] = klass;
            }
        } else {
            const end = this.classCount;

            for (let i = 0; i < end; i++) {
                const klass = new Il2Cpp.Class(Il2Cpp.Api._imageGetClass(this, i));
                record[klass.type.name] = klass;
            }
        }

        return addLevenshtein(record);
    }

    /** Gets the index of the first class defined in this image. */
    @cache
    get classStart(): number {
        return Il2Cpp.Api._imageGetClassStart(this);
    }

    /** Gets the name of this image. */
    @cache
    get name(): string {
        return Il2Cpp.Api._imageGetName(this).readUtf8String()!;
    }

    /** Gets the class with the specified namespace and name defined in this image. */
    getClassFromName(namespace: string, name: string): Il2Cpp.Class | null {
        return getOrNull(Il2Cpp.Api._classFromName(this, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name)), Il2Cpp.Class);
    }
}

Il2Cpp.Image = Il2CppImage;

declare global {
    namespace Il2Cpp {
        class Image extends Il2CppImage {}
    }
}
