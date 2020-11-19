import Api from "./api";
import Il2CppObject from "./object";

/** @internal */
export default class Il2CppString {
    constructor(readonly handle: NativePointer) {}

    get content() {
        return Api._stringChars(this.handle).readUtf16String(this.length);
    }

    set content(value) {
        if (value != null) {
            Api._stringChars(this.handle).writeUtf16String(value);
            Api._stringSetLength(this.handle, value.length);
        }
    }

    get length() {
        return Api._stringLength(this.handle);
    }

    get object() {
        return new Il2CppObject(this.handle);
    }

    static from(content: string) {
        return new Il2CppString(Api._stringNew(content));
    }

    toString() {
        return this.content;
    }
}
