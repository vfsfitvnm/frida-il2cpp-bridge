import { cache } from "decorator-cache-getter";

import { addLevenshtein } from "../../utils/record";

import { Api } from "../api";
import { getOrNull, NativeStructNotNull } from "../../utils/native-struct";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("Image")
class Il2CppImage extends NativeStructNotNull {
    @cache
    get classCount(): number {
        return Api._imageGetClassCount(this.handle);
    }

    @cache
    get classStart(): number {
        return Api._imageGetClassStart(this.handle);
    }

    @cache
    get classes(): Readonly<Record<string, Il2Cpp.Class>> {
        const record: Record<string, Il2Cpp.Class> = {};

        if (Il2Cpp.unityVersion.isLegacy) {
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
                const klass = new Il2Cpp.Class(Api._imageGetClass(this.handle, i));
                record[klass.type.name] = klass;
            }
        }

        return addLevenshtein(record);
    }

    @cache
    get name(): string {
        return Api._imageGetName(this.handle)!;
    }

    getClassFromName(namespace: string, name: string): Il2Cpp.Class | null {
        return getOrNull(Api._classFromName(this.handle, namespace, name), Il2Cpp.Class);
    }
}
