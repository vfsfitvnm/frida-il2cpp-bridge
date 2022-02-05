import { cache } from "decorator-cache-getter";
import { NativeStruct } from "../../utils/native-struct";
import { getOrNull } from "../../utils/utils";
import { checkNull } from "../decorators";

/** Represents a `Il2CppObject`. */
class Il2CppObject extends NativeStruct {
    /** Gets the class of this object. */
    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._objectGetClass(this));
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

    /** Gets the field with the given name. */
    field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> {
        return this.class.field<T>(name)!.withHolder(this);
    }

    /** Gets the field with the given name. */
    method<R extends Il2Cpp.Method.ReturnType, A extends Il2Cpp.Parameter.Type[] | [] = any[]>(
        name: string,
        parameterCount: number = -1
    ): Il2Cpp.Method<R, A> {
        return this.class.method<R, A>(name, parameterCount)!.withHolder(this);
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
    override toString(): string {
        return this.method<Il2Cpp.String, []>("ToString").invoke().content || "null";
    }
}

Il2Cpp.Object = Il2CppObject;

declare global {
    namespace Il2Cpp {
        class Object extends Il2CppObject {}
    }
}
