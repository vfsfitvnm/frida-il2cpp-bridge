import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { NativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("String")
class Il2CppString extends NativeStruct {
    get content(): string | null {
        if (this.handle.isNull()) {
            return null;
        }
        return Api._stringChars(this).readUtf16String(this.length);
    }

    set content(value: string | null) {
        if (value != null && !this.handle.isNull()) {
            Api._stringChars(this).writeUtf16String(value);
            Api._stringSetLength(this, value.length);
        }
    }

    get length(): number {
        if (this.handle.isNull()) {
            return 0;
        }
        return Api._stringLength(this);
    }

    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(this);
    }

    static from(content: string | null): Il2Cpp.String {
        if (content == null) {
            return new Il2Cpp.String(NULL);
        }
        return new Il2Cpp.String(Api._stringNew(content));
    }

    toString(): string | null {
        return this.content;
    }
}
