import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { getOrNull, NonNullNativeStruct } from "../../utils/native-struct";
import { addLevenshtein } from "../../utils/utils";

@injectToIl2Cpp("Image")
class Il2CppImage extends NonNullNativeStruct {
    @cache
    get classCount(): number {
        return Api._imageGetClassCount(this);
    }

    @cache
    get classes(): Readonly<Record<string, Il2Cpp.Class>> {
        const record: Record<string, Il2Cpp.Class> = {};

        if (Il2Cpp.unityVersion.isBefore2018_3_0) {
            const start = this.classStart;
            const end = start + this.classCount;

            const globalIndex = Memory.alloc(Process.pointerSize);
            globalIndex.add(Il2Cpp.Type.offsetOfTypeEnum).writeInt(0x20);

            for (let i = start; i < end; i++) {
                const klass = new Il2Cpp.Class(Api._typeGetClassOrElementClass(globalIndex.writeInt(i)));
                record[klass.type!.name!] = klass;
            }
        } else {
            const end = this.classCount;

            for (let i = 0; i < end; i++) {
                const klass = new Il2Cpp.Class(Api._imageGetClass(this, i));
                record[klass.type.name] = klass;
            }
        }

        return addLevenshtein(record);
    }

    @cache
    get classStart(): number {
        return Api._imageGetClassStart(this);
    }

    @cache
    get name(): string {
        return Api._imageGetName(this).readUtf8String()!;
    }

    getClassFromName(namespace: string, name: string): Il2Cpp.Class | null {
        return getOrNull(Api._classFromName(this, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name)), Il2Cpp.Class);
    }
}
