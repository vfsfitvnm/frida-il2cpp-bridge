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
     * @return The size of each element.
     */
    @cache
    get elementSize(): number {
        if (this.handle.isNull()) {
            return 0;
        }
        return this.object.class.type.dataType!.class.arrayElementSize;
    }

    /**
     * @return The type of its elements.
     */
    @cache
    get elementType(): _Il2CppType {
        return this.object.class.type.dataType!;
    }

    /** @internal */
    @cache
    get elements(): NativePointer {
        if (this.handle.isNull()) {
            return NULL;
        }
        return Api._arrayGetElements(this.handle);
    }

    /**
     * @return Its length.
     */
    @cache
    get length(): number {
        if (this.handle.isNull()) {
            return 0;
        }
        return Api._arrayGetLength(this.handle);
    }

    /**
     * @return The same array as an object.
     */
    @cache
    get object(): _Il2CppObject {
        return new _Il2CppObject(this.handle);
    }

    /**
     * Creates a new array.
     * @param klass The class of the elements.
     * @param elements The elements.
     * @return A new array.
     */
    static from<T extends AllowedType>(klass: _Il2CppClass, elements: T[]): _Il2CppArray<T> {
        const handle = Api._arrayNew(klass.handle, elements.length);
        const array = new _Il2CppArray<T>(handle);
        elements.forEach((e, i) => array.set(i, e));
        return array;
    }

    /**
     * @param index The index of the element. It must be between the array bounds.
     * @return The element at the given index.
     */
    @checkOutOfBounds
    get(index: number): T {
        return readFieldValue(this.elements.add(index * this.elementSize), this.elementType) as T;
    }

    /**
     * @param index The index of the element. It must be between the array bounds.
     * @param value The value of the element.
     */
    @checkOutOfBounds
    set(index: number, value: T) {
        writeFieldValue(this.elements.add(index * this.elementSize), value, this.elementType);
    }

    /**
     * Iterable.
     */
    *[Symbol.iterator](): IterableIterator<T> {
        for (let i = 0; i < this.length; i++) yield this.get(i);
    }
}
