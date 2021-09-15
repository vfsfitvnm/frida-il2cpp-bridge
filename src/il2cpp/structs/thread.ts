import { cache } from "decorator-cache-getter";
import { NativeStruct } from "../../utils/native-struct";
import { getOrNull } from "../../utils/utils";

/** Represents a `Il2CppThread`. */
class Il2CppThread extends NativeStruct {
    /** Gets the attached threads. */
    static get all(): Il2CppThread[] {
        const array: Il2Cpp.Thread[] = [];

        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Il2Cpp.Api._threadGetAllAttachedThreads(sizePointer);

        const size = sizePointer.readInt();

        for (let i = 0; i < size; i++) {
            array.push(new Il2Cpp.Thread(startPointer.add(i * Process.pointerSize).readPointer()));
        }

        return array;
    }

    /** Gets the current attached thread, if any. */
    static get current(): Il2CppThread | null {
        return getOrNull(Il2Cpp.Api._threadCurrent(), Il2CppThread);
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

    /** Detaches the thread from the application domain. */
    detach(): void {
        return Il2Cpp.Api._threadDetach(this);
    }
}

Il2Cpp.Thread = Il2CppThread;

declare global {
    namespace Il2Cpp {
        class Thread extends Il2CppThread {}
    }
}
