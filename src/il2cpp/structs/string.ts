import { Api } from "../api";
import { Il2CppObject } from "./object";
import { NativeStruct } from "../native-struct";

/**
 * Represents a `Il2CppString`.
 * ```typescript
 * const str = Il2Cpp.String.from("Hello!");
 * //
 * assert(str.content == "Hello!");
 * //
 * str.content = "Bye";
 * assert(str.content == "Bye");
 * //
 * assert(str.length == 3);
 * assert(str.content?.length == 3);
 * //
 * assert(str.object.class.type.name == "System.String");
 * assert(str.object.class.type.typeEnum == Il2Cpp.TypeEnum.STRING);
 * ```
 */
export class Il2CppString extends NativeStruct {
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
        return new Il2CppObject(this.handle);
    }

    /**
     * Creates a new string.
     * @param content The string content.
     * @return A new string.
     */
    static from(content: string) {
        return new Il2CppString(Api._stringNew(content));
    }

    /**
     * @return The string content.
     */
    toString() {
        return this.content;
    }
}
