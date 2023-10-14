namespace Il2Cpp {
    export class String extends NativeStruct {
        /** Gets the content of this string. */
        get content(): string | null {
            return Il2Cpp.api.stringGetChars(this).readUtf16String(this.length);
        }

        /** @unsafe Sets the content of this string - it may write out of bounds! */
        set content(value: string | null) {
            // prettier-ignore
            const offset = Il2Cpp.string("vfsfitvnm").handle.offsetOf(_ => _.readInt() == 9) 
                ?? raise("couldn't find the length offset in the native string struct");

            globalThis.Object.defineProperty(Il2Cpp.String.prototype, "content", {
                set(this: Il2Cpp.String, value: string | null) {
                    Il2Cpp.api.stringGetChars(this).writeUtf16String(value ?? "");
                    this.handle.add(offset).writeS32(value?.length ?? 0);
                }
            });

            this.content = value;
        }

        /** Gets the length of this string. */
        get length(): number {
            return Il2Cpp.api.stringGetLength(this);
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
        return new Il2Cpp.String(Il2Cpp.api.stringNew(Memory.allocUtf8String(content ?? "")));
    }
}
