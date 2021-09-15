import { cache } from "decorator-cache-getter";
import { isBelow } from "./decorators";
import { getOrNull } from "../utils/utils";

class Il2CppMetadata {
    protected constructor() {}

    /** @internal */
    @cache
    static get dummyImage(): Il2Cpp.Image {
        return Il2Cpp.Image.corlib;
    }

    /** @internal */
    @cache
    static get dummyType(): NativePointer {
        return Memory.alloc(Process.pointerSize);
    }

    /** Gets the class corresponding to the given index. */
    @isBelow("2020.2.0")
    static getClass(index: number): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._typeGetClassOrElementClass(this.dummyType.writeS32(index)));
    }

    /** Gets the method corresponding to the given index. */
    static getMethod(index: number): Il2Cpp.Method | null {
        Il2Cpp.Api._imageSetEntryPointIndex(this.dummyImage, index);

        return getOrNull(Il2Cpp.Api._imageGetEntryPoint(this.dummyImage), Il2Cpp.Method);
    }
}

Il2Cpp.Metadata = Il2CppMetadata;

declare global {
    namespace Il2Cpp {
        class Metadata extends Il2CppMetadata {}
    }
}
