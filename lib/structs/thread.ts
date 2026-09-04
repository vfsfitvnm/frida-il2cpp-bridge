namespace Il2Cpp {
    export class Thread extends NativeStruct {
        /**
         * Gets the managed thread associated with the given native thread id (if any).
         *
         * This is an alternative to {@link Il2Cpp.attachedThreads}:
         * ```ts
         * async function findAllThreads() {
         *     const promises = Process.enumerateThreads().map(thread => Il2Cpp.Thread.fromId(thread.id));
         *     return (await Promise.all(promises)).filter(thread => thread != null);
         * }
         * ```
         */
        static fromId(threadId: number): Promise<Il2Cpp.Thread | null> {
            return Process.runOnThread(threadId, () => Il2Cpp.currentThread);
        }

        /** Gets the native id of the current thread, or -1 if it is somehow missing. */
        get id(): number {
            let get = function (this: Il2Cpp.Thread) {
                return this.internal.field<UInt64>("thread_id").value.toNumber();
            };

            // https://github.com/mono/linux-packaging-mono/blob/d586f84dfea30217f34b076a616a098518aa72cd/mono/utils/mono-threads.h#L642
            if (Process.platform != "windows") {
                const currentThreadId = Process.getCurrentThreadId();
                const currentPosixThread = ptr(get.apply(Il2Cpp.currentThread!));

                // prettier-ignore
                const offset = currentPosixThread.offsetOf(_ => _.readS32() == currentThreadId, 1024) ??
                    raise(`couldn't find the offset for determining the kernel id of a posix thread`);

                const _get = get;
                get = function (this: Il2Cpp.Thread) {
                    const handle = ptr(_get.apply(this));
                    // sometimes, for some thread, there is no info...
                    if (handle.isNull()) {
                        warn(`couldn't find thread id for ${this.handle}; returning a negative number, expect breakage`);
                        return -1;
                    }
                    return handle.add(offset).readS32();
                };
            }

            getter(Il2Cpp.Thread.prototype, "id", get, lazy);

            return this.id;
        }

        /** Gets the encompassing internal object (System.Threding.InternalThreead) of the current thread. */
        @lazy
        get internal(): Il2Cpp.Object {
            return this.object.tryField<Il2Cpp.Object>("internal_thread")?.value ?? this.object;
        }

        /** Determines whether the current thread is the garbage collector finalizer one. */
        @lazy
        get isFinalizer(): boolean {
            return !Il2Cpp.exports.threadIsVm(this);
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
        private get synchronizationContext(): Il2Cpp.Object | null {
            const get_ExecutionContext = this.object.tryMethod<Il2Cpp.Object>("GetMutableExecutionContext") ?? this.object.method("get_ExecutionContext");
            const executionContext = get_ExecutionContext.invoke();

            // From what I observed, only the main thread is supposed to have a
            // synchronization context; however there are two cases where it is
            // not available at all:
            // 1) during early instrumentation;
            // 2) it was dead code has it was stripped out.
            const synchronizationContext =
                executionContext.tryField<Il2Cpp.Object>("_syncContext")?.value ??
                executionContext.tryMethod<Il2Cpp.Object>("get_SynchronizationContext")?.invoke() ??
                this.tryLocalValue(Il2Cpp.corlib.class("System.Threading.SynchronizationContext"));

            return synchronizationContext?.asNullable() ?? null;
        }

        /** Detaches the thread from the application domain. */
        detach(): void {
            return Il2Cpp.exports.threadDetach(this);
        }

        /** Schedules a callback on the current thread. */
        schedule<T>(block: () => T): Promise<T> {
            const Post = this.synchronizationContext?.tryMethod("Post");

            if (Post == null) {
                return Process.runOnThread(this.id, block);
            }

            return new Promise(resolve => {
                const delegate = Il2Cpp.delegate(Il2Cpp.corlib.class("System.Threading.SendOrPostCallback"), () => {
                    const result = block();
                    setImmediate(() => resolve(result));
                });

                // This is to replace pending scheduled callbacks when the script is about to get unlaoded.
                // If we skip this cleanup, Frida's native callbacks will point to invalid memory, making
                // the application crash as soon as the IL2CPP runtime tries to execute such callbacks.
                // For instance, without the following code, this is how you can trigger a crash:
                // 1) unfocus the application;
                // 2) schedule a callback;
                // 3) reload the script;
                // 4) focus application.
                //
                // The "proper" solution consists in removing our delegates from the Unity synchroniztion
                // context, but the interface is not consisent across Unity versions - e.g. 2017.4.40f1 uses
                // a queue instead of a list, whereas newer versions do not allow null work requests.
                // The following solution, which basically redirects the invocation to a native function that
                // survives the script reloading, is much simpler, honestly.
                Script.bindWeak(globalThis, () => {
                    delegate.field("method_ptr").value = delegate.field("invoke_impl").value = Il2Cpp.exports.domainGet;
                });

                Post.invoke(delegate, NULL);
            });
        }

        /** @internal */
        tryLocalValue(klass: Il2Cpp.Class): Il2Cpp.Object | undefined {
            for (let i = 0; i < 16; i++) {
                const base = this.staticData.add(i * Process.pointerSize).readPointer();
                if (!base.isNull()) {
                    const object = new Il2Cpp.Object(base.readPointer()).asNullable();
                    if (object?.class?.isSubclassOf(klass, false)) {
                        return object;
                    }
                }
            }
        }
    }

    /** Gets the threads attached to IL2CPP. */
    export declare const attachedThreads: Il2Cpp.Thread[];
    getter(Il2Cpp, "attachedThreads", () => {
        if (Il2Cpp.exports.threadGetAttachedThreads.isNull()) {
            // attached threads are stored in s_AttachedThreads (a std::vector in libil2cpp/vm/Thread.cpp)
            // in case il2cpp_thread_get_all_attached_threads is not available, we can scan the
            // memory to look for the current thread pointer, so that we get where s_AttachedThreads
            // is contiguously storing its values (pointers to threads)
            const currentThread = Il2Cpp.currentThread ?? raise("current thread is not attached to IL2CPP");
            const pattern = currentThread.handle.toMatchPattern();

            // s_AttachedThreads is initialized at runtime (il2cpp_init) and it is managed by IL2CPP GC
            const rangeProvider = function* () {
                // ranges allocated by IL2CPP garbage collector
                try {
                    yield* Il2Cpp.gc.heapSections;
                } catch (_) {} // ignore missing export or native exceptions

                // ranges where other static data allocated during il2cpp_init is
                yield Process.getRangeByAddress(Il2Cpp.corlib.assembly.object);
                yield Process.getRangeByAddress(Il2Cpp.corlib.class("System.Threading.Thread").staticFieldsData);

                // last resort: every range in the whole process that is likely to be heap allocated
                yield* Process.enumerateRanges("rw-").filter(_ => _.file == undefined);
            };

            for (const range of rangeProvider()) {
                let matches: MemoryScanMatch[] = [];
                try {
                    // TODO: replace with Memory.findPointers once it's stable
                    matches = Memory.scanSync(range.base, range.size, pattern);
                } catch (_) {} // ignore access violation errors (https://github.com/vfsfitvnm/frida-il2cpp-bridge/issues/742)

                if (matches.length == 1) {
                    const threads: Il2Cpp.Thread[] = [];
                    const iter = (index: number) => {
                        const handle = matches[0].address.add(index * Process.pointerSize).readPointer();

                        // reject obvious non-pointers
                        if (!handle.isNull() && Process.findRangeByAddress(handle) != null) {
                            // try interpret the handle as an actual thread - Il2CppThread is a
                            // Il2CppObject, so class addresses should match
                            const thread = new Il2Cpp.Thread(handle);
                            if (thread.object.class.equals(currentThread.object.class)) {
                                return threads.push(thread);
                            }
                        }
                    };

                    for (let i = 0; iter(i); i--); // find previous threads
                    threads.reverse();
                    for (let i = 1; iter(i); i++); // find next threads

                    return threads;
                }
            }

            raise("couldn't collect attached threads");
        }

        return readNativeList(Il2Cpp.exports.threadGetAttachedThreads).map(_ => new Il2Cpp.Thread(_));
    });

    /** Gets the current attached thread, if any. */
    export declare const currentThread: Il2Cpp.Thread | null;
    getter(Il2Cpp, "currentThread", () => {
        return new Il2Cpp.Thread(Il2Cpp.exports.threadGetCurrent()).asNullable();
    });

    /** Gets the current attached thread, if any. */
    export declare const mainThread: Il2Cpp.Thread;
    getter(Il2Cpp, "mainThread", () => {
        // I'm not sure if this is always the case. Typically, the main
        // thread managed id is 1, but this isn't always true: spawning
        // an Android application with Unity 5.3.8f1 will cause the Frida
        // thread to have the managed id equal to 1, whereas the main thread
        // managed id is 2.
        return attachedThreads[0];
    });
}
