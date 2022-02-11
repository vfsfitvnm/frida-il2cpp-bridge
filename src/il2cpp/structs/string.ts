import { NativeStruct } from "../../utils/native-struct";

/** Represents a `Il2CppString`. */
class Il2CppString extends NativeStruct {
    /** Gets the content of this string. */
    get content(): string | null {
        return Il2Cpp.Api._stringChars(this).readUtf16String(this.length);
    }

    /** Sets the content of this string. */
    set content(value: string | null) {
        Il2Cpp.Api._stringChars(this).writeUtf16String(value ?? "");
        Il2Cpp.Api._stringSetLength(this, value?.length ?? 0);
    }

    /** Gets the length of this string. */
    get length(): number {
        return Il2Cpp.Api._stringLength(this);
    }

    /** Gets the encompassing object of the current string. */
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(this);
    }

    /** */
    toString(): string {
        return this.isNull() ? "null" : `"${this.content}"`;
    }

    /** Creates a new string with the specified content. */
    static from(content: string | null): Il2Cpp.String {
        return new Il2Cpp.String(Il2Cpp.Api._stringNew(Memory.allocUtf8String(content || "")));
    }
}

Il2Cpp.String = Il2CppString;

declare global {
    namespace Il2Cpp {
        class String extends Il2CppString {}
    }
}
