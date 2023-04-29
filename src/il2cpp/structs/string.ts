namespace Il2Cpp {
    export class String extends NativeStruct {
        /** Gets the content of this string. */
        get content(): string | null {
            return Il2Cpp.Api.stringChars(this).readUtf16String(this.length);
        }

        /** Sets the content of this string. */
        set content(value: string | null) {
            Il2Cpp.Api.stringChars(this).writeUtf16String(value ?? "");
            Il2Cpp.Api.stringSetLength(this, value?.length ?? 0);
        }

        /** Gets the length of this string. */
        get length(): number {
            return Il2Cpp.Api.stringLength(this);
        }

        /** Gets the encompassing object of the current string. */
        get object(): Il2Cpp.Object {
            return new Il2Cpp.Object(this);
        }

        /** */
        toString(): string {
            return this.isNull() ? "null" : `"${this.content}"`;
        }
    }

    /** Creates a new string with the specified content. */
    export function string(content: string | null): Il2Cpp.String {
        return new Il2Cpp.String(Il2Cpp.Api.stringNew(Memory.allocUtf8String(content ?? "")));
    }
}
