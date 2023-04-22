namespace Il2Cpp {
    export class Object extends NativeStruct {
        /** Gets the Il2CppObject struct size, possibly equal to `Process.pointerSize * 2`. */
        @lazy
        static get headerSize(): number {
            return Il2Cpp.corlib.class("System.Object").instanceSize;
        }

        /** Gets the class of this object. */
        @lazy
        get class(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.Api.objectGetClass(this));
        }

        /** Gets the size of the current object. */
        @lazy
        get size(): number {
            return Il2Cpp.Api.objectGetSize(this);
        }

        /** Acquires an exclusive lock on the current object. */
        enter(): void {
            return Il2Cpp.Api.monitorEnter(this);
        }

        /** Release an exclusive lock on the current object. */
        exit(): void {
            return Il2Cpp.Api.monitorExit(this);
        }

        /** Gets the field with the given name. */
        field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> {
            return this.class.field<T>(name).withHolder(this);
        }

        /** Gets the method with the given name. */
        method<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.Method<T> {
            return this.class.method<T>(name, parameterCount).withHolder(this);
        }

        /** Notifies a thread in the waiting queue of a change in the locked object's state. */
        pulse(): void {
            return Il2Cpp.Api.monitorPulse(this);
        }

        /** Notifies all waiting threads of a change in the object's state. */
        pulseAll(): void {
            return Il2Cpp.Api.monitorPulseAll(this);
        }

        /** Creates a reference to this object. */
        ref(pin: boolean): Il2Cpp.GCHandle {
            return new Il2Cpp.GCHandle(Il2Cpp.Api.gcHandleNew(this, +pin));
        }

        /** Gets the correct virtual method from the given virtual method. */
        virtualMethod<T extends Il2Cpp.Method.ReturnType>(method: Il2Cpp.Method): Il2Cpp.Method<T> {
            return new Il2Cpp.Method<T>(Il2Cpp.Api.objectGetVirtualMethod(this, method)).withHolder(this);
        }

        /** Attempts to acquire an exclusive lock on the current object. */
        tryEnter(timeout: number): boolean {
            return !!Il2Cpp.Api.monitorTryEnter(this, timeout);
        }

        /** Gets the field with the given name. */
        tryField<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> | undefined {
            return this.class.tryField<T>(name)?.withHolder(this);
        }

        /** Gets the field with the given name. */
        tryMethod<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.Method<T> | undefined {
            return this.class.tryMethod<T>(name, parameterCount)?.withHolder(this);
        }

        /** Releases the lock on an object and attempts to block the current thread until it reacquires the lock. */
        tryWait(timeout: number): boolean {
            return !!Il2Cpp.Api.monitorTryWait(this, timeout);
        }

        /** */
        toString(): string {
            return this.isNull() ? "null" : this.method<Il2Cpp.String>("ToString").invoke().content ?? "null";
        }

        /** Unboxes the value type out of this object. */
        unbox(): Il2Cpp.ValueType {
            return new Il2Cpp.ValueType(Il2Cpp.Api.objectUnbox(this), this.class.type);
        }

        /** Releases the lock on an object and blocks the current thread until it reacquires the lock. */
        wait(): void {
            return Il2Cpp.Api.monitorWait(this);
        }

        /** Creates a weak reference to this object. */
        weakRef(trackResurrection: boolean): Il2Cpp.GCHandle {
            return new Il2Cpp.GCHandle(Il2Cpp.Api.gcHandleNewWeakRef(this, +trackResurrection));
        }
    }
}
