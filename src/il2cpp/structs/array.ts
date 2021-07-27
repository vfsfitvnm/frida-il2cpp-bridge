import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { checkNull, injectToIl2Cpp } from "../decorators";

import { raise } from "../../utils/console";
import { NativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("Array")
class Il2CppArray<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends NativeStruct implements Iterable<T> {
    static from<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type>(klass: Il2Cpp.Class, elements: T[]): Il2Cpp.Array<T> {
        const array = new Il2Cpp.Array<T>(Api._arrayNew(klass, elements.length));
        array.elements.values = elements;
        return array;
    }

    @cache
    get elements(): Il2Cpp.Pointer<T> {
        return new Il2Cpp.Pointer(Api._arrayGetElements(this), this.elementType);
    }

    @cache
    get elementSize(): number {
        return this.elementType.class.arrayElementSize;
    }

    @cache
    get elementType(): Il2Cpp.Type {
        return this.object.class.type.dataType!;
    }

    @cache
    get length(): number {
        return Api._arrayGetLength(this);
    }

    @cache
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(this);
    }

    get(index: number): T {
        checkIndexOutOfBounds(this, index);
        return this.elements.get(index);
    }

    set(index: number, value: T) {
        checkIndexOutOfBounds(this, index);
        this.elements.set(index, value);
    }

    @checkNull
    override toString(): string {
        return this.elements.toString();
    }

    *[Symbol.iterator](): IterableIterator<T> {
        for (let i = 0; i < this.length; i++) {
            yield this.elements.get(i);
        }
    }
}

function checkIndexOutOfBounds(array: Il2CppArray, index: number): void {
    if (index < 0 || index >= array.length) {
        raise(`${array.constructor.name} element index '${index}' out of bounds (length: ${array.length}).`);
    }
}
