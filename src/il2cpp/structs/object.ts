import { cache } from "decorator-cache-getter";
import { checkNull } from "../decorators";
import { NativeStruct } from "../../utils/native-struct";
import { addLevenshtein, filterMap, getOrNull, makeIterable, overridePropertyValue } from "../../utils/utils";

/** Represents a `Il2CppObject`. */
class Il2CppObject extends NativeStruct {
    /** Allocates a new object of the specified class. */
    static from(klass: Il2Cpp.Class): Il2Cpp.Object {
        return new Il2Cpp.Object(Il2Cpp.Api._objectNew(klass));
    }

    /** Gets this object casted to its base type. */
    @cache
    get base(): Il2Cpp.Object {
        return overridePropertyValue(new Il2Cpp.Object(this), "class", this.class.parent!);
    }

    /** Gets the class of this object. */
    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._objectGetClass(this));
    }

    /** Gets the fields of this object. */
    @cache
    get fields(): IterableRecord<Il2Cpp.Field> {
        return makeIterable(
            addLevenshtein(
                filterMap(
                    this.class.fields,
                    (field: Il2Cpp.Field) => !field.isStatic,
                    (field: Il2Cpp.Field) => field.withHolder(this)
                )
            )
        );
    }

    /** Gets the methods of this object. */
    @cache
    get methods(): IterableRecord<Il2Cpp.Method> {
        return makeIterable(
            addLevenshtein(
                filterMap(
                    this.class.methods,
                    (method: Il2Cpp.Method) => !method.isStatic,
                    (method: Il2Cpp.Method) => method.withHolder(this)
                )
            )
        );
    }

    /** Gets the size of the current object. */
    @cache
    get size(): number {
        return Il2Cpp.Api._objectGetSize(this);
    }

    /** Acquires an exclusive lock on the current object. */
    enter(): void {
        return Il2Cpp.Api._monitorEnter(this);
    }

    /** Release an exclusive lock on the current object. */
    exit(): void {
        return Il2Cpp.Api._monitorExit(this);
    }

    /** */
    getVirtualMethod(method: Il2Cpp.Method): Il2Cpp.Method | null {
        return getOrNull(Il2Cpp.Api._objectGetVirtualMethod(this, method), Il2Cpp.Method);
    }

    /** Notifies a thread in the waiting queue of a change in the locked object's state. */
    pulse(): void {
        return Il2Cpp.Api._monitorPulse(this);
    }

    /** Notifies all waiting threads of a change in the object's state. */
    pulseAll(): void {
        return Il2Cpp.Api._monitorPulseAll(this);
    }

    /** Creates a reference to this object. */
    ref(pin: boolean): Il2Cpp.GC.Handle {
        return new Il2Cpp.GC.Handle(Il2Cpp.Api._gcHandleNew(this, +pin));
    }

    /** Attempts to acquire an exclusive lock on the current object. */
    tryEnter(timeout: number): boolean {
        return !!Il2Cpp.Api._monitorTryEnter(this, timeout);
    }

    /** Releases the lock on an object and attempts to block the current thread until it reacquires the lock. */
    tryWait(timeout: number): boolean {
        return !!Il2Cpp.Api._monitorTryWait(this, timeout);
    }

    /** Unboxes the value type out of this object. */
    unbox(): NativePointer {
        return Il2Cpp.Api._objectUnbox(this);
    }

    /** Releases the lock on an object and blocks the current thread until it reacquires the lock. */
    wait(): void {
        return Il2Cpp.Api._monitorWait(this);
    }

    /** Creates a weak reference to this object. */
    weakRef(trackResurrection: boolean): Il2Cpp.GC.Handle {
        return new Il2Cpp.GC.Handle(Il2Cpp.Api._gcHandleNewWeakRef(this, +trackResurrection));
    }

    @checkNull
    override toString(): string | null {
        let object: Il2Cpp.Object = this;
        while (!("ToString" in object.methods)) {
            object = object.base;
        }

        return object.methods.ToString.invoke<Il2Cpp.String>().content;
    }
}

Il2Cpp.Object = Il2CppObject;

declare global {
    namespace Il2Cpp {
        class Object extends Il2CppObject {}
    }
}
