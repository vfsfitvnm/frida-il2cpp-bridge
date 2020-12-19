import Api from "./api";
import { lazy } from "../utils/decorators";
import Il2CppClass from "./class";
import Il2CppType from "./type";
import { raise } from "../utils/console";
import { AllowedType, readFieldValue, Valuable, writeFieldValue } from "./runtime";

/** @internal */
export default class Il2CppField implements Valuable {
    private static readonly THREAD_STATIC_FIELD_OFFSET = -1;

    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get class() {
        return new Il2CppClass(Api._fieldGetClass(this.handle));
    }

    @lazy get isInstance() {
        return Api._fieldIsInstance(this.handle);
    }

    @lazy get isLiteral() {
        return Api._fieldIsLiteral(this.handle);
    }

    @lazy get isThreadStatic() {
        return this.offset == Il2CppField.THREAD_STATIC_FIELD_OFFSET;
    }

    @lazy get name() {
        return Api._fieldGetName(this.handle)!;
    }

    @lazy get offset() {
        return Api._fieldGetOffset(this.handle);
    }

    @lazy get type() {
        return new Il2CppType(Api._fieldGetType(this.handle));
    }

    get value() {
        return readFieldValue(this.valueHandle, this.type!);
    }

    set value(v) {
        if (this.isInstance) {
            raise(`Cannot access the instance field "${this.name}" without an instance.`);
        } else if (this.isThreadStatic || this.isLiteral) {
            raise(`Cannot edit the thread static or literal field "${this.name}".`);
        }
        writeFieldValue(this.valueHandle, v, this.type!);
    }

    get valueHandle() {
        let handle: NativePointer;
        if (this.isInstance) {
            raise(`Cannot access the instance field "${this.name}" without an instance.`);
        } else if (this.isThreadStatic || this.isLiteral) {
            handle = Memory.alloc(Process.pointerSize);
            Api._fieldGetStaticValue(this.handle, handle);
        } else {
            handle = this.class.staticFieldsData.add(this.offset);
        }
        return handle;
    }

    asHeld(handle: NativePointer) {
        if (!this.isInstance) {
            raise(`"${this.name}" is a static field.`);
        }
        const type = this.type;
        return {
            valueHandle: handle,
            get value() {
                return readFieldValue(handle, type);
            },
            set value(v) {
                writeFieldValue(handle, v, type);
            }
        } as Valuable;
    }
}
