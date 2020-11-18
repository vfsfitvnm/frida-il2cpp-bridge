import Il2CppClass from "./class";
import Api from "./api";
import { lazy } from "../utils/decorators";
import UnityVersion from "../utils/unity-version";
import Il2CppType from "./type";
import { Accessor } from "../utils/accessor";
import { raise } from "../utils/console";
import { getOrNull } from "../utils/helpers";

/** @internal */
export default class Il2CppImage {
    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get classCount() {
        return Api._imageGetClassCount(this.handle);
    }

    @lazy get classStart() {
        return UnityVersion.CURRENT.isBelow("2020.2.0") ? Api._imageGetClassStart(this.handle) : -1;
    }

    @lazy get classes() {
        const accessor = new Accessor<Il2CppClass>();
        const start = this.classStart;
        if (UnityVersion.CURRENT.isEqualOrAbove("2018.3.0")) {
            const end = this.classCount;
            for (let i = 0; i < end; i++) {
                const klass = new Il2CppClass(Api._imageGetClass(this.handle, i));
                accessor[klass.type!.name!] = klass;
            }
        } else {
            const end = start + this.classCount;
            const globalIndex = Memory.alloc(Process.pointerSize);
            globalIndex.add(Il2CppType.offsetOfTypeEnum).writeInt(0x20);
            for (let i = start; i < end; i++) {
                const klass = new Il2CppClass(Api._typeGetClassOrElementClass(globalIndex.writeInt(i)));
                accessor[klass.type!.name!] = klass;
            }
        }
        return accessor;
    }

    @lazy get name() {
        return Api._imageGetName(this.handle)!;
    }

    getClassFromName(namespace: string, name: string) {
        return getOrNull(Api._classFromName(this.handle, namespace, name), Il2CppClass);
    }
}
