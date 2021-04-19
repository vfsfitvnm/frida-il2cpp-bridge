import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { checkOutOfBounds, nonNullHandle } from "../decorators";
import { NativeStruct } from "../native-struct";
import { AllowedType } from "../types";
import { readFieldValue, writeFieldValue } from "../utils";

import { _Il2CppClass } from "./class";
import { _Il2CppObject } from "./object";

/**
 * Represents a `Il2CppArraySize`.
 */
@nonNullHandle
export class _Il2CppArray<T extends AllowedType> extends NativeStruct implements Iterable<T> {
    /**
     * @return The size of each element.
     */
    @cache get elementSize() {
        return this.object.class.type.dataType!.class.arrayElementSize;
    }

    /**
     * @return The type of its elements.
     */
    @cache get elementType() {
        return this.object.class.type.dataType!;
    }

    /** @internal */
    @cache get elements() {
        return Api._arrayGetElements(this.handle);
    }

    /**
     * @return Its length.
     */
    @cache get length() {
        return Api._arrayGetLength(this.handle);
    }

    /**
     * @return The same array as an object.
     */
    @cache get object() {
        return new _Il2CppObject(this.handle);
    }

    /**
     * Creates a new array.
     * @param klass The class of the elements.
     * @param elements The elements.
     * @return A new array.
     */
    static from<T extends AllowedType>(klass: _Il2CppClass, elements: T[]) {
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
    get(index: number) {
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
    *[Symbol.iterator]() {
        for (let i = 0; i < this.length; i++) yield this.get(i);
    }
}
