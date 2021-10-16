import { cache } from "decorator-cache-getter";
import { checkNull } from "../decorators";
import { NativeStruct } from "../../utils/native-struct";
import { addLevenshtein, filterMap, IterableRecord, makeIterable } from "../../utils/utils";

/** Value type class utility. */
class Il2CppValueType extends NativeStruct {
    constructor(handle: NativePointer, readonly type: Il2Cpp.Type) {
        super(handle);
    }

    /** Gets the fields of this value type. */
    @cache
    get fields(): IterableRecord<Il2Cpp.Field> {
        return makeIterable(
            addLevenshtein(
                filterMap(
                    this.type.class.fields,
                    (field: Il2Cpp.Field) => !field.isStatic,
                    (field: Il2Cpp.Field) => field.withHolder(this)
                )
            )
        );
    }

    /** Boxes the current value type in a object. */
    box(): Il2Cpp.Object {
        return new Il2Cpp.Object(Il2Cpp.Api._valueBox(this.type.class, this));
    }

    @checkNull
    override toString(): string {
        return this.box().toString();
    }
}

Il2Cpp.ValueType = Il2CppValueType;

declare global {
    namespace Il2Cpp {
        class ValueType extends Il2CppValueType {}
    }
}
