import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { checkOutOfBounds } from "../decorators";
import { NativeStruct } from "../native-struct";
import { AllowedType } from "../types";
import { readFieldValue, writeFieldValue } from "../utils";

import { _Il2CppClass } from "./class";
import { _Il2CppObject } from "./object";
import { _Il2CppType } from "./type";

/**
 * Represents a `Il2CppArraySize`.
 */
export class _Il2CppArray<T extends AllowedType> extends NativeStruct implements Iterable<T> {

    /**
     * Gets the size of the object encompassed by the current array.
     */
    @cache
    get elementSize(): number {
        if (this.handle.isNull()) {
            return 0;
        }
        return this.object.class.type.dataType!.class.arrayElementSize;
    }

    /**
     * Gets the type of the object encompassed by the current array.
     */
    @cache
    get elementType(): _Il2CppType {
        return this.object.class.type.dataType!;
    }

    /**
     * Gets a pointer to the first element of the current array.
     * @internal
     */
    @cache
    get elements(): NativePointer {
        if (this.handle.isNull()) {
            return NULL;
        }
        return Api._arrayGetElements(this.handle);
    }

    /**
     * Gets the total number of elements in all the dimensions of the current array.
     */
    @cache
    get length(): number {
        if (this.handle.isNull()) {
            return 0;
        }
        return Api._arrayGetLength(this.handle);
    }

    /**
     * Gets the object behind the current array.
     */
    @cache
    get object(): _Il2CppObject {
        return new _Il2CppObject(this.handle);
    }

    /**
     * Creates a new array.
     */
    static from<T extends AllowedType>(klass: _Il2CppClass, elements: T[]): _Il2CppArray<T> {
        const handle = Api._arrayNew(klass.handle, elements.length);
        const array = new _Il2CppArray<T>(handle);
        elements.forEach((e, i) => array.set(i, e));
        return array;
    }

    /**
     * Gets the element at the specified index of the current array.
     */
    @checkOutOfBounds
    get(index: number): T {
        return readFieldValue(this.elements.add(index * this.elementSize), this.elementType) as T;
    }

    /**
     * Sets the element at the specified index of the current array.
     */
    @checkOutOfBounds
    set(index: number, value: T) {
        writeFieldValue(this.elements.add(index * this.elementSize), value, this.elementType);
    }

    /**
     * Iterable.
     */
    *[Symbol.iterator](): IterableIterator<T> {
        for (let i = 0; i < this.length; i++) {
            yield this.get(i);
        }
    }
}