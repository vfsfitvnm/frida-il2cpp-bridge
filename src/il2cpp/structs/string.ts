import { Api } from "../api";
import { NativeStruct } from "../native-struct";

import { _Il2CppObject } from "./object";

/**
 * Represents a `Il2CppString`.
 */
export class _Il2CppString extends NativeStruct {
    /**
     * @return Its actual content.
     */
    get content() {
        return Api._stringChars(this.handle).readUtf16String(this.length);
    }

    /**
     * @param value The new content.
     */
    set content(value) {
        if (value != null) {
            Api._stringChars(this.handle).writeUtf16String(value);
            Api._stringSetLength(this.handle, value.length);
        }
    }

    /**
     * @return Its length.
     */
    get length() {
        return Api._stringLength(this.handle);
    }

    /**
     * @return The same string as an object.
     */
    get object() {
        return new _Il2CppObject(this.handle);
    }

    /**
     * Creates a new string.
     * @param content The string content.
     * @return A new string.
     */
    static from(content: string) {
        return new _Il2CppString(Api._stringNew(content));
    }

    /**
     * @return The string content.
     */
    toString() {
        return this.content;
    }
}
