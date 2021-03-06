import { Api } from "../api";
import { since } from "../decorators";
import { Il2CppObject } from "./object";
import { Il2CppString } from "./string";
import { Il2CppArray } from "./array";
import { AllowedType } from "../types";
import { Il2CppClass } from "./class";
import { Il2CppTypeEnum } from "./type-enum";
import { Il2CppMemorySnapshot } from "./memory-snapshot";

/**
 * Garbage collector utility functions.
 */
export class Il2CppGC {
    /**
     * Forces the GC to collect object from the given
     * [generation](https://docs.microsoft.com/en-us/dotnet/standard/garbage-collection/fundamentals#generations).
     * @param generation The category of objects to collect.
     */
    static collect(generation: 0 | 1 | 2) {
        Api._gcCollect(generation);
    }

    /**
     * Like {@link Il2CppGC.collect | collect}, but I don't know which
     * generation it collects.
     */
    @since("5.3.5")
    static collectALittle() {
        Api._gcCollectALittle();
    }

    /**
     * Disables the GC.
     */
    @since("5.3.5")
    static disable() {
        Api._gcDisable();
    }

    /**
     * Enables the GC.
     */
    @since("5.3.5")
    static enable() {
        Api._gcEnable();
    }

    /**
     * @return `true` if the GC is disabled, `false` otherwise.
     */
    @since("2018.3.0")
    static isDisabled() {
        return Api._gcIsDisabled();
    }

    /**
     * It reads the GC descriptor of the given class and looks for its objects
     * on the heap. During this process, it may stop and start the GC world
     * multiple times.\
     * A version with callbacks is not really needed because:
     * - There aren't performance issues;
     * - It cannot be stopped;
     * - The `onMatch` callback can only be called when the GC world starts again,
     * but the whole thing is enough fast it doesn't make any sense to have
     * callbacks.
     *
     * ```typescript
     * const StringClass = Il2Cpp.domain.assemblies.mscorlib.image.classes["System.String"];
     * const matches = Il2Cpp.GC.choose<Il2Cpp.String>(StringClass);
     * for (const match of matches) {
     *     console.log(match);
     * }
     * ```
     * @template T Type parameter to automatically cast the objects to other object-like
     * entities, like string and arrays. Default is {@link Il2CppObject}.
     * @param klass The class of the objects you are looking for.
     * @return An array of ready-to-use objects, strings or arrays. Value types are boxed.
     */
    static choose<T extends Il2CppObject | Il2CppString | Il2CppArray<AllowedType> = Il2CppObject>(klass: Il2CppClass): T[] {
        const isString = klass.type.typeEnum == Il2CppTypeEnum.STRING;
        const isArray = klass.type.typeEnum == Il2CppTypeEnum.SZARRAY;

        const matches: T[] = [];

        const callback = (objects: NativePointer, size: number, _: NativePointer) => {
            for (let i = 0; i < size; i++) {
                const pointer = objects.add(i * Process.pointerSize).readPointer();

                if (isString) matches.push(new Il2CppString(pointer) as T);
                else if (isArray) matches.push(new Il2CppArray(pointer) as T);
                else matches.push(new Object(pointer) as T);
            }
        };

        const chooseCallback = new NativeCallback(callback, "void", ["pointer", "int", "pointer"]);
        const onWorld = new NativeCallback(() => {}, "void", []);

        const state = Api._livenessCalculationBegin(klass.handle, 0, chooseCallback, NULL, onWorld, onWorld);
        Api._livenessCalculationFromStatics(state);
        Api._livenessCalculationEnd(state);

        return matches;
    }

    /**
     * It takes a memory snapshot and scans the current tracked objects of the given class.\
     * It leads to different results if compared to {@link Il2CppGC.choose}.
     * @template T Type parameter to automatically cast the objects to other object-like
     * entities, like string and arrays. Default is {@link Il2CppObject}.
     * @param klass The class of the objects you are looking for.
     * @return An array of ready-to-use objects, strings or arrays. Value types are boxed.
     */
    static choose2<T extends Il2CppObject | Il2CppString | Il2CppArray<AllowedType> = Il2CppObject>(klass: Il2CppClass): T[] {
        const isString = klass.type.typeEnum == Il2CppTypeEnum.STRING;
        const isArray = klass.type.typeEnum == Il2CppTypeEnum.SZARRAY;

        const matches: T[] = [];

        const snapshot = new Il2CppMemorySnapshot();
        const count = snapshot.trackedObjectCount.toNumber();
        const start = snapshot.objectsPointer;

        for (let i = 0; i < count; i++) {
            const pointer = start.add(i * Process.pointerSize).readPointer();
            const object = new Il2CppObject(pointer);

            if (object.class.handle.equals(klass.handle)) {
                if (isString) matches.push(new Il2CppString(pointer) as T);
                else if (isArray) matches.push(new Il2CppArray(pointer) as T);
                else matches.push(object as T);
            }
        }

        snapshot.free();

        return matches;
    }
}
