import { cache } from "decorator-cache-getter";
import { raise } from "../../utils/console";
import { NativeStruct } from "../../utils/native-struct";

/** Represents a `Il2CppThread`. */
class Il2CppThread extends NativeStruct {
    /** @internal */
    @cache
    private static get idOffset(): number {
        const internalThread = Il2Cpp.currentThread?.object.tryField<Il2Cpp.Object>("internal_thread")?.value;
        const object = internalThread ? internalThread : Il2Cpp.currentThread!.object;

        const handle = ptr(object.field<UInt64>("thread_id").value.toString());
        const currentThreadId = Process.getCurrentThreadId();

        for (let i = 0; i < 1024; i++) {
            const candidate = handle.add(i).readS32();
            if (candidate == currentThreadId) {
                return i;
            }
        }

        raise(`couldn't determine the offset for a native thread id value`);
    }

    /** Gets the native id of the current thread. */
    get id(): number {
        return ptr(this.internal.field<UInt64>("thread_id").value.toString()).add(Il2Cpp.Thread.idOffset).readS32();
    }

    /** Gets the encompassing internal object (System.Threding.InternalThreead) of the current thread. */
    @cache
    private get internal(): Il2Cpp.Object {
        const internalThread = this.object.tryField<Il2Cpp.Object>("internal_thread")?.value;
        return internalThread ? internalThread : this.object;
    }

    /** Determines whether the current thread is the garbage collector finalizer one. */
    get isFinalizer(): boolean {
        return !Il2Cpp.Api._threadIsVm(this);
    }

    /** Gets the encompassing object of the current thread. */
    @cache
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(this);
    }

    /** */
    @cache
    private get staticData(): NativePointer {
        return this.internal.field<NativePointer>("static_data").value;
    }

    @cache
    private get synchronizationContext(): Il2Cpp.Object {
        const get_ExecutionContext =
            this.object.tryMethod<Il2Cpp.Object>("GetMutableExecutionContext") || this.object.method("get_ExecutionContext");

        let synchronizationContext = get_ExecutionContext.invoke().tryMethod<Il2Cpp.Object>("get_SynchronizationContext")?.invoke();

        if (synchronizationContext == null) {
            const SystemThreadingSynchronizationContext = Il2Cpp.Image.corlib.class("System.Threading.SynchronizationContext");

            for (let i = 0; i < 16; i++) {
                try {
                    const candidate = new Il2Cpp.Object(
                        this.staticData
                            .add(Process.pointerSize * i)
                            .readPointer()
                            .readPointer()
                    );
                    if (new Il2Cpp.Object(candidate).class.isSubclassOf(SystemThreadingSynchronizationContext, false)) {
                        synchronizationContext = candidate;
                        break;
                    }
                } catch (e) {}
            }
        }

        if (synchronizationContext == null) {
            raise("couldn't retrieve the SynchronizationContext for this thread.");
        }

        return synchronizationContext;
    }

    /** Detaches the thread from the application domain. */
    detach(): void {
        return Il2Cpp.Api._threadDetach(this);
    }

    /** Schedules a callback on the current thread. */
    async schedule<T>(block: () => T | Promise<T>): Promise<T> {
        const thisThreadId = this.id;

        const GetDisplayName = Il2Cpp.Image.corlib.class("Mono.Runtime").method("GetDisplayName");

        const SystemThreadingSendOrPostCallback = Il2Cpp.Image.corlib.class("System.Threading.SendOrPostCallback");

        const SendOrPostCallback = SystemThreadingSendOrPostCallback.alloc();
        SendOrPostCallback.method(".ctor").invoke(NULL, GetDisplayName.handle);

        return new Promise<T>(resolve => {
            const listener = Interceptor.attach(GetDisplayName.virtualAddress, function () {
                if (this.threadId == thisThreadId) {
                    listener.detach();
                    const result = block();
                    setImmediate(() => resolve(result));
                }
            });

            this.synchronizationContext.method("Post").invoke(SendOrPostCallback, NULL);
        });
    }
}

Il2Cpp.Thread = Il2CppThread;

declare global {
    namespace Il2Cpp {
        class Thread extends Il2CppThread {}
    }
}
