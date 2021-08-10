import { cache } from "decorator-cache-getter";

import { checkNull } from "../decorators";

import { raise } from "../../utils/console";
import { NativeStruct } from "../../utils/native-struct";

/** Represents a `Il2CppArraySize`. */
class Il2CppArray<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends NativeStruct implements Iterable<T> {
    /** Creates a new array. */
    static from<T extends Il2Cpp.Field.Type>(klass: Il2Cpp.Class, elements: T[]): Il2Cpp.Array<T> {
        const array = new Il2Cpp.Array<T>(Il2Cpp.Api._arrayNew(klass, elements.length));
        array.elements.values = elements;
        return array;
    }

    /** @internal Gets a pointer to the first element of the current array. */
    @cache
    get elements(): Il2Cpp.Pointer<T> {
        return new Il2Cpp.Pointer(Il2Cpp.Api._arrayGetElements(this), this.elementType);
    }

    /** Gets the size of the object encompassed by the current array. */
    @cache
    get elementSize(): number {
        return this.elementType.class.arrayElementSize;
    }

    /** Gets the type of the object encompassed by the current array. */
    @cache
    get elementType(): Il2Cpp.Type {
        return this.object.class.type.dataType!;
    }

    /** Gets the total number of elements in all the dimensions of the current array. */
    @cache
    get length(): number {
        return Il2Cpp.Api._arrayGetLength(this);
    }

    /** Gets the encompassing object of the current array. */
    @cache
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(this);
    }

    /** @internal */
    checkIndexOutOfBounds(index: number): void {
        if (index < 0 || index >= this.length) {
            raise(`${this.constructor.name} element index '${index}' out of bounds (length: ${this.length}).`);
        }
    }

    /** Gets the element at the specified index of the current array. */
    get(index: number): T {
        this.checkIndexOutOfBounds(index);
        return this.elements.get(index);
    }

    /** Sets the element at the specified index of the current array. */
    set(index: number, value: T) {
        this.checkIndexOutOfBounds(index);
        this.elements.set(index, value);
    }

    @checkNull
    override toString(): string {
        return this.elements.toString();
    }

    /** Iterable. */
    *[Symbol.iterator](): IterableIterator<T> {
        for (let i = 0; i < this.length; i++) {
            yield this.elements.get(i);
        }
    }
}

Il2Cpp.Array = Il2CppArray;

declare global {
    namespace Il2Cpp {
        class Array<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends Il2CppArray<T> {}
    }
}
