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
    get content(): string | null {
        if (this.handle.isNull()) {
            return null;
        }
        return Api._stringChars(this.handle).readUtf16String(this.length);
    }

    /**
     * @param value The new content.
     */
    set content(value: string | null) {
        if (value != null && !this.handle.isNull()) {
            Api._stringChars(this.handle).writeUtf16String(value);
            Api._stringSetLength(this.handle, value.length);
        }
    }

    /**
     * @return Its length.
     */
    get length(): number {
        if (this.handle.isNull()) {
            return 0;
        }
        return Api._stringLength(this.handle);
    }

    /**
     * @return The same string as an object.
     */
    get object(): _Il2CppObject {
        return new _Il2CppObject(this.handle);
    }

    /**
     * Creates a new string.
     * @param content The string content.
     * @return A new string.
     */
    static from(content: string): _Il2CppString {
        return new _Il2CppString(Api._stringNew(content));
    }

    /**
     * @return The string content.
     */
    toString(): string | null {
        return this.content;
    }
}
