import { since } from "../decorators";

/** Garbage collector utility functions. */
class Il2CppGC {
    protected constructor() {}

    /** Gets the heap size in bytes. */
    static get heapSize(): Int64 {
        return Il2Cpp.Api._gcGetHeapSize();
    }

    /** Determines whether the garbage collector is disabled. */
    @since("2018.3.0", "5.3.5")
    static get isEnabled(): boolean {
        return !Il2Cpp.Api._gcIsDisabled();
    }

    /** Gets the used heap size in bytes. */
    static get usedHeapSize(): Int64 {
        return Il2Cpp.Api._gcGetUsedSize();
    }

    /** Enables or disables the garbage collector. */
    static set isEnabled(value: boolean) {
        value ? Il2Cpp.Api._gcEnable() : Il2Cpp.Api._gcDisable();
    }

    /** Returns the heap allocated objects of the specified class. This variant reads GC descriptors. */
    static choose(klass: Il2Cpp.Class): Il2Cpp.Object[] {
        const matches: Il2Cpp.Object[] = [];

        const callback = (objects: NativePointer, size: number, _: NativePointer) => {
            for (let i = 0; i < size; i++) {
                matches.push(new Il2Cpp.Object(objects.add(i * Process.pointerSize).readPointer()));
            }
        };

        const chooseCallback = new NativeCallback(callback, "void", ["pointer", "int", "pointer"]);
        const onWorld = new NativeCallback(() => {}, "void", []);

        const state = Il2Cpp.Api._livenessCalculationBegin(klass.handle, 0, chooseCallback, NULL, onWorld, onWorld);
        Il2Cpp.Api._livenessCalculationFromStatics(state);
        Il2Cpp.Api._livenessCalculationEnd(state);

        return matches;
    }

    /** Forces a garbage collection of the specified generation. */
    static collect(generation: 0 | 1 | 2): void {
        Il2Cpp.Api._gcCollect(generation < 0 ? 0 : generation > 2 ? 2 : generation);
    }

    /** Forces a garbage collection. */
    @since("5.3.5")
    static collectALittle(): void {
        Il2Cpp.Api._gcCollectALittle();
    }
}

Reflect.set(Il2Cpp, "GC", Il2CppGC);

declare global {
    namespace Il2Cpp {
        class GC extends Il2CppGC {}
    }
}
