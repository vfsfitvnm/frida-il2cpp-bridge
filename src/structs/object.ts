namespace Il2Cpp {
    export class Object extends Il2Cpp.InstanceType {
        /** Gets the Il2CppObject struct size, possibly equal to `Process.pointerSize * 2`. */
        @lazy
        static get headerSize(): number {
            return Il2Cpp.corlib.class("System.Object").instanceSize;
        }

        /**
         * Returns the same object, but having its parent class as class.
         * It basically is the C# `base` keyword, so that parent members can be
         * accessed.
         *
         * **Example** \
         * Consider the following classes:
         * ```csharp
         * class Foo
         * {
         *     int foo()
         *     {
         *          return 1;
         *     }
         * }
         * class Bar : Foo
         * {
         *     new int foo()
         *     {
         *          return 2;
         *     }
         * }
         * ```
         * then:
         * ```ts
         * const Bar: Il2Cpp.Class = ...;
         * const bar = Bar.new();
         *
         * console.log(bar.foo()); // 2
         * console.log(bar.base.foo()); // 1
         * ```
         */
        get base(): Il2Cpp.Object {
            if (this.class.parent == null) {
                raise(`class ${this.class.type.name} has no parent`);
            }

            return new Proxy(this, {
                get(target: Il2Cpp.Object, property: keyof Il2Cpp.Object, receiver: Il2Cpp.Object): any {
                    if (property == "class") {
                        return Reflect.get(target, property).parent;
                    } else if (property == "base") {
                        return Reflect.getOwnPropertyDescriptor(Il2Cpp.Object.prototype, property)!.get!.bind(receiver)();
                    }
                    return Reflect.get(target, property);
                }
            });
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

        /** Creates a reference to this object. */
        ref(pin: boolean): Il2Cpp.GCHandle {
            return new Il2Cpp.GCHandle(Il2Cpp.exports.gcHandleNew(this, +pin));
        }

        /** Gets the correct virtual method from the given virtual method. */
        virtualMethod<T extends Il2Cpp.Method.ReturnType>(method: Il2Cpp.Method): Il2Cpp.BoundMethod<T> {
            return new Il2Cpp.Method<T>(Il2Cpp.exports.objectGetVirtualMethod(this, method)).bind(this);
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
