import { Api } from "../api";
import { injectToIl2Cpp, checkNull } from "../decorators";

import { NativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("String")
class Il2CppString extends NativeStruct {
    static from(content: string | null): Il2Cpp.String {
        return new Il2Cpp.String(Api._stringNew(Memory.allocUtf8String(content || "")));
    }

    get content(): string | null {
        return Api._stringChars(this).readUtf16String(this.length);
    }

    get length(): number {
        return Api._stringLength(this);
    }

    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(this);
    }

    set content(value: string | null) {
        Api._stringChars(this).writeUtf16String(value || "");
        Api._stringSetLength(this, value?.length || 0);
    }

    @checkNull
    override toString(): string | null {
        return `"${this.content}"`;
    }
}
