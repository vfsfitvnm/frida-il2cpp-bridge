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
            return new Il2Cpp.Class(Il2Cpp.exports.objectGetClass(this));
        }

        /** Returns a monitor for this object. */
        get monitor(): Il2Cpp.Object.Monitor {
            return new Il2Cpp.Object.Monitor(this);
        }

        /** Gets the size of the current object. */
        @lazy
        get size(): number {
            return Il2Cpp.exports.objectGetSize(this);
        }

        /** Gets the field with the given name. */
        field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.BoundField<T> {
            return this.class.field<T>(name).bind(this);
        }

        /** Gets the method with the given name. */
        method<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.BoundMethod<T> {
            return this.class.method<T>(name, parameterCount).bind(this);
        }

        /** Creates a reference to this object. */
        ref(pin: boolean): Il2Cpp.GCHandle {
            return new Il2Cpp.GCHandle(Il2Cpp.exports.gcHandleNew(this, +pin));
        }

        /** Gets the correct virtual method from the given virtual method. */
        virtualMethod<T extends Il2Cpp.Method.ReturnType>(method: Il2Cpp.Method): Il2Cpp.BoundMethod<T> {
            return new Il2Cpp.Method<T>(Il2Cpp.exports.objectGetVirtualMethod(this, method)).bind(this);
        }

        /** Gets the field with the given name. */
        tryField<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.BoundField<T> | undefined {
            return this.class.tryField<T>(name)?.bind(this);
        }

        /** Gets the field with the given name. */
        tryMethod<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.BoundMethod<T> | undefined {
            return this.class.tryMethod<T>(name, parameterCount)?.bind(this);
        }

        /** */
        toString(): string {
            return this.isNull() ? "null" : this.method<Il2Cpp.String>("ToString", 0).invoke().content ?? "null";
        }

        /** Unboxes the value type (either a primitive, a struct or an enum) out of this object. */
        unbox(): Il2Cpp.ValueType {
            return this.class.isValueType
                ? new Il2Cpp.ValueType(Il2Cpp.exports.objectUnbox(this), this.class.type)
                : raise(`couldn't unbox instances of ${this.class.type.name} as they are not value types`);
        }

        /** Creates a weak reference to this object. */
        weakRef(trackResurrection: boolean): Il2Cpp.GCHandle {
            return new Il2Cpp.GCHandle(Il2Cpp.exports.gcHandleNewWeakRef(this, +trackResurrection));
        }
    }

    export namespace Object {
        export class Monitor {
            /** @internal */
            constructor(/** @internal */ readonly handle: NativePointerValue) {}

            /** Acquires an exclusive lock on the current object. */
            enter(): void {
                return Il2Cpp.exports.monitorEnter(this.handle);
            }

            /** Release an exclusive lock on the current object. */
            exit(): void {
                return Il2Cpp.exports.monitorExit(this.handle);
            }

            /** Notifies a thread in the waiting queue of a change in the locked object's state. */
            pulse(): void {
                return Il2Cpp.exports.monitorPulse(this.handle);
            }

            /** Notifies all waiting threads of a change in the object's state. */
            pulseAll(): void {
                return Il2Cpp.exports.monitorPulseAll(this.handle);
            }

            /** Attempts to acquire an exclusive lock on the current object. */
            tryEnter(timeout: number): boolean {
                return !!Il2Cpp.exports.monitorTryEnter(this.handle, timeout);
            }

            /** Releases the lock on an object and attempts to block the current thread until it reacquires the lock. */
            tryWait(timeout: number): boolean {
                return !!Il2Cpp.exports.monitorTryWait(this.handle, timeout);
            }

            /** Releases the lock on an object and blocks the current thread until it reacquires the lock. */
            wait(): void {
                return Il2Cpp.exports.monitorWait(this.handle);
            }
        }
    }
}
