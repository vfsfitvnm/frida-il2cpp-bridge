import Api from "./api";
import { lazy } from "../utils/decorators";
import { raise } from "../utils/console";
import { AllowedType, readFieldValue, writeFieldValue } from "./runtime";
import Il2CppObject from "./object";
import Il2CppClass from "./class";

/** @internal */
export default class Il2CppArray<T extends AllowedType> implements Iterable<T> {
    constructor(readonly handle: NativePointer) {
        if (this.handle.isNull()) {
            raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }
    }

    @lazy get elementSize() {
        return this.object.class!.type!.dataType!.class!.arrayElementSize;
    }

    @lazy get elementType() {
        return this.object.class!.type!.dataType!;
    }

    @lazy get elements() {
        return Api._arrayGetElements(this.handle);
    }

    @lazy get length() {
        return Api._arrayGetLength(this.handle);
    }

    @lazy get object() {
        return new Il2CppObject(this.handle);
    }

    static from<T extends AllowedType>(klass: Il2CppClass, elements: T[]) {
        const handle = Api._arrayNew(klass.handle, elements.length);
        const array = new Il2CppArray<T>(handle);
        elements.forEach((e, i) => array.set(i, e));
        return array;
    }

    get(index: number) {
        if (index < 0 || index >= this.length) {
            raise(`Array index '${index}' out of bounds (length: ${this.length}).`);
        }
        return readFieldValue(this.elements.add(index * this.elementSize), this.elementType) as T;
    }

    set(index: number, v: T) {
        if (index < 0 || index >= this.length) {
            raise(`Array index '${index}' out of bounds (length: ${this.length}).`);
        }
        writeFieldValue(this.elements.add(index * this.elementSize), v, this.elementType);
    }

    *[Symbol.iterator]() {
        for (let i = 0; i < this.length; i++) yield this.get(i);
    }
}
