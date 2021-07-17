import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { readFieldValue, writeFieldValue } from "../utils";

import { NativeStruct } from "../../utils/native-struct";
import { raise } from "../../utils/console";
import { injectToIl2Cpp } from "../decorators";

@injectToIl2Cpp("Array")
class Il2CppArray<T extends Il2Cpp.AllowedType> extends NativeStruct implements Iterable<T> {
    @cache
    get elementSize(): number {
        if (this.handle.isNull()) {
            return 0;
        }
        return this.object.class.type.dataType!.class.arrayElementSize;
    }

    @cache
    get elementType(): Il2Cpp.Type {
        return this.object.class.type.dataType!;
    }

    @cache
    get elements(): NativePointer {
        if (this.handle.isNull()) {
            return NULL;
        }
        return Api._arrayGetElements(this.handle);
    }

    @cache
    get length(): number {
        if (this.handle.isNull()) {
            return 0;
        }
        return Api._arrayGetLength(this.handle);
    }

    @cache
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(this.handle);
    }

    static from<T extends Il2Cpp.AllowedType>(klass: Il2Cpp.Class, elements: T[]): Il2Cpp.Array<T> {
        const handle = Api._arrayNew(klass.handle, elements.length);
        const array = new Il2Cpp.Array<T>(handle);

        elements.forEach((e: T, i: number) => array.set(i, e));

        return array;
    }

    get(index: number): T {
        checkIndexOutOfBounds(this, index);
        return readFieldValue(this.elements.add(index * this.elementSize), this.elementType) as T;
    }

    set(index: number, value: T) {
        checkIndexOutOfBounds(this, index);
        writeFieldValue(this.elements.add(index * this.elementSize), value, this.elementType);
    }

    override toString(): string {
        return `[${Array.from(this).join(", ")}]`;
    }

    *[Symbol.iterator](): IterableIterator<T> {
        for (let i = 0; i < this.length; i++) {
            yield this.get(i);
        }
    }
}

function checkIndexOutOfBounds(array: Il2CppArray<Il2Cpp.AllowedType>, index: number): void {
    if (index < 0 || index >= array.length) {
        raise(`${array.constructor.name} element index '${index}' out of bounds (length: ${array.length}).`);
    }
}
