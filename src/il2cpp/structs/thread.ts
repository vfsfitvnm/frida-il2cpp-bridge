namespace Il2Cpp {
    export class Thread extends NativeStruct {
        /** Gets the native id of the current thread. */
        @lazy
        get id(): number {
            const id = this.internal.field<UInt64>("thread_id").value.toNumber();
            return Process.platform == "windows" ? id : posixThreadGetKernelId(ptr(id));
        }

        /** Gets the encompassing internal object (System.Threding.InternalThreead) of the current thread. */
        @lazy
        get internal(): Il2Cpp.Object {
            return this.object.tryField<Il2Cpp.Object>("internal_thread")?.value ?? this.object;
        }

        /** Determines whether the current thread is the garbage collector finalizer one. */
        @lazy
        get isFinalizer(): boolean {
            return !Il2Cpp.api.threadIsVm(this);
        }

        /** Gets the managed id of the current thread. */
        @lazy
        get managedId(): number {
            return this.object.method<number>("get_ManagedThreadId").invoke();
        }

        /** Gets the encompassing object of the current thread. */
        @lazy
        get object(): Il2Cpp.Object {
            return new Il2Cpp.Object(this);
        }

        /** @internal */
        @lazy
        private get staticData(): NativePointer {
            return this.internal.field<NativePointer>("static_data").value;
        }

        /** @internal */
        @lazy
        private get synchronizationContext(): Il2Cpp.Object {
            const get_ExecutionContext = this.object.tryMethod<Il2Cpp.Object>("GetMutableExecutionContext") ?? this.object.method("get_ExecutionContext");
            const executionContext = get_ExecutionContext.invoke();

            let synchronizationContext =
                executionContext.tryField<Il2Cpp.Object>("_syncContext")?.value ??
                executionContext.tryMethod<Il2Cpp.Object>("get_SynchronizationContext")?.invoke() ??
                this.tryLocalValue(Il2Cpp.corlib.class("System.Threading.SynchronizationContext"));

            if (synchronizationContext == null || synchronizationContext.isNull()) {
                if (this.managedId == 1) {
                    raise(`couldn't find the synchronization context of the main thread, perhaps this is early instrumentation?`);
                } else {
                    raise(`couldn't find the synchronization context of thread #${this.managedId}, only the main thread is expected to have one`);
                }
            }

            return synchronizationContext;
        }

        /** Detaches the thread from the application domain. */
        detach(): void {
            return Il2Cpp.api.threadDetach(this);
        }

        /** Schedules a callback on the current thread. */
        schedule<T>(block: () => T | Promise<T>, delayMs: number = 0): Promise<T> {
            const Post = this.synchronizationContext.method("Post");

            return new Promise(resolve => {
                const delegate = Il2Cpp.delegate(Il2Cpp.corlib.class("System.Threading.SendOrPostCallback"), () => {
                    const result = block();
                    setImmediate(() => resolve(result));
                });

                if (delayMs > 0) {
                    setTimeout(() => Post.invoke(delegate, NULL), delayMs);
                } else {
                    Post.invoke(delegate, NULL);
                }
            });
        }

        /** @internal */
        tryLocalValue(klass: Il2Cpp.Class): Il2Cpp.Object | undefined {
            for (let i = 0; i < 16; i++) {
                const base = this.staticData.add(i * Process.pointerSize).readPointer();
                if (!base.isNull()) {
                    const object = new Il2Cpp.Object(base.readPointer());
                    if (!object.isNull() && object.class.isSubclassOf(klass, false)) {
                        return object;
                    }
                }
            }
        }
    }

    /** Gets the attached threads. */
    export declare const attachedThreads: Il2Cpp.Thread[];
    getter(Il2Cpp, "attachedThreads", () => {
        return readNativeList(Il2Cpp.api.threadGetAllAttachedThreads).map(_ => new Il2Cpp.Thread(_));
    });

    /** Gets the current attached thread, if any. */
    export declare const currentThread: Il2Cpp.Thread | null;
    getter(Il2Cpp, "currentThread", () => {
        const handle = Il2Cpp.api.threadCurrent();
        return handle.isNull() ? null : new Il2Cpp.Thread(handle);
    });

    /** Gets the current attached thread, if any. */
    export declare const mainThread: Il2Cpp.Thread;
    getter(Il2Cpp, "mainThread", () => {
        // I'm not sure if this is always the case. Alternatively, we could pick the thread
        // with the lowest managed id, but I'm not sure that always holds true, either.
        return attachedThreads[0];
    });

    /** @internal */
    let posixThreadKernelIdOffset = -1;

    /** @internal */
    function posixThreadGetKernelId(posixThread: NativePointer): number {
        if (posixThreadKernelIdOffset == -1) {
            const currentPosixThread = ptr(Il2Cpp.currentThread!.internal.field<UInt64>("thread_id").value.toNumber());
            const currentThreadId = Process.getCurrentThreadId();

            for (let i = 0; i < 1024; i++) {
                if (currentPosixThread.add(i).readS32() == currentThreadId) {
                    posixThreadKernelIdOffset = i;
                    break;
                }
            }

            if (posixThreadKernelIdOffset == -1) {
                raise(`couldn't find the offset for determining the kernel id of a posix thread`);
            }
        }

        return posixThread.add(posixThreadKernelIdOffset).readS32();
    }
}
