import { cache } from "decorator-cache-getter";

import { Api } from "il2cpp/api";
import { checkOutOfBounds, nonNullHandle } from "il2cpp/decorators";
import { NativeStruct } from "il2cpp/native-struct";
import { AllowedType } from "il2cpp/types";
import { readFieldValue, writeFieldValue } from "il2cpp/utils";

import { _Il2CppClass } from "./class";
import { _Il2CppObject } from "./object";

/**
 * Represents a `Il2CppArraySize`.
 * ```typescript
 * const mscorlib = Il2Cpp.domain.assemblies.mscorlib.image;
 * //
 * const SingleClass = mscorlib.classes["System.Single"];
 * //
 * const array = Il2Cpp.Array.from<number>(SingleClass, [21.5, 55.3, 31.4, 33]);
 * //
 * assert(array.elementSize == SingleClass.arrayElementSize);
 * //
 * assert(array.length == 4);
 * //
 * assert(array.object.class.type.name == "System.Single[]");
 * //
 * assert(array.elementType.name == "System.Single");
 * //
 * assert(array.object.class.type.typeEnum == Il2Cpp.TypeEnum.SZARRAY);
 * //
 * assert(array.get(0) == 21.5);
 * //
 * array.set(0, 5);
 * assert(array.get(0) == 5);
 * //
 * let str = "";
 * for (const e of array) {
 *     str += Math.ceil(e) + ",";
 * }
 * assert(str == "5,56,32,33,");
 * ```
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
