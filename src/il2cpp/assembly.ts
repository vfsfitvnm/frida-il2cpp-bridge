import Api from "./api";
import { lazy } from "../utils/decorators";
import UnityVersion from "../utils/unity-version";
import Il2CppImage from "./image";
import { raise } from "../utils/console";

/** @internal */
export default class Il2CppAssembly {
    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get image() {
        return new Il2CppImage(Api._assemblyGetImage(this.handle));
    }

    @lazy get name() {
        if (UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")) {
            return Api._assemblyGetName(this.handle)!;
        }
        return this.image.name.replace(".dll", "");
    }
}
