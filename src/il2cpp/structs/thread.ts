namespace Il2Cpp {
    export class Thread extends NativeStruct {
        /** @internal */
        @lazy
        private static get idOffset(): number {
            const handle = ptr(Il2Cpp.currentThread!.internal.field<UInt64>("thread_id").value.toString());
            const currentThreadId = Process.getCurrentThreadId();

            for (let i = 0; i < 1024; i++) {
                try {
                    const candidate = handle.add(i).readS32();
                    if (candidate == currentThreadId) {
                        return i;
                    }
                } catch (e: any) {}
            }

            raise(`couldn't determine the offset for a native thread id value`);
        }

        /** Gets the native id of the current thread. */
        @lazy
        get id(): number {
            return ptr(this.internal.field<UInt64>("thread_id").value.toString()).add(Il2Cpp.Thread.idOffset).readS32();
        }

        /** Gets the encompassing internal object (System.Threding.InternalThreead) of the current thread. */
        @lazy
        get internal(): Il2Cpp.Object {
            return this.object.tryField<Il2Cpp.Object>("internal_thread")?.value ?? this.object;
        }

        /** Determines whether the current thread is the garbage collector finalizer one. */
        @lazy
        get isFinalizer(): boolean {
            return !Il2Cpp.Api.threadIsVm(this);
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
            const get_ExecutionContext = this.object.tryMethod<Il2Cpp.Object>("GetMutableExecutionContext") || this.object.method("get_ExecutionContext");
            const executionContext = get_ExecutionContext.invoke();

            let synchronizationContext =
                executionContext.tryField<Il2Cpp.Object>("_syncContext")?.value ??
                executionContext.tryMethod<Il2Cpp.Object>("get_SynchronizationContext")?.invoke();

            if (synchronizationContext == null) {
                const SystemThreadingSynchronizationContext = Il2Cpp.corlib.class("System.Threading.SynchronizationContext");

                for (let i = 0; i < 16; i++) {
                    try {
                        const candidate = new Il2Cpp.Object(
                            this.staticData
                                .add(Process.pointerSize * i)
                                .readPointer()
                                .readPointer()
                        );
                        if (candidate.class.isSubclassOf(SystemThreadingSynchronizationContext, false)) {
                            synchronizationContext = candidate;
                            break;
                        }
                    } catch (e) {}
                }
            }

            if (synchronizationContext == null || synchronizationContext.isNull()) {
                raise("couldn't retrieve the SynchronizationContext for this thread.");
            }

            return synchronizationContext;
        }

        /** Detaches the thread from the application domain. */
        detach(): void {
            return Il2Cpp.Api.threadDetach(this);
        }

        /** Schedules a callback on the current thread. */
        schedule<T>(block: () => T | Promise<T>, delayMs: number = 0): Promise<T> {
            return new Promise(resolve => {
                const delegate = Il2Cpp.delegate(Il2Cpp.corlib.class("System.Threading.SendOrPostCallback"), () => {
                    const result = block();
                    setImmediate(() => resolve(result));
                });

                const post = this.synchronizationContext.method("Post").invoke.bind(null, delegate, NULL);

                if (delayMs > 0) {
                    setTimeout(post, delayMs);
                } else {
                    post();
                }
            });
        }
    }

    /** Gets the attached threads. */
    export declare const attachedThreads: Il2Cpp.Thread[];
    getter(Il2Cpp, "attachedThreads", () => {
        return readNativeList(Il2Cpp.Api.threadGetAllAttachedThreads).map(_ => new Il2Cpp.Thread(_));
    });

    /** Gets the current attached thread, if any. */
    export declare const currentThread: Il2Cpp.Thread | null;
    getter(Il2Cpp, "currentThread", () => {
        const handle = Il2Cpp.Api.threadCurrent();
        return handle.isNull() ? null : new Il2Cpp.Thread(handle);
    });

    /** Gets the current attached thread, if any. */
    export declare const mainThread: Il2Cpp.Thread;
    getter(Il2Cpp, "mainThread", () => {
        // I'm not sure if this is always the case. Alternatively, we could pick the thread
        // with the lowest managed id, but I'm not sure that always holds true, either.
        return attachedThreads[0];
    });
}
