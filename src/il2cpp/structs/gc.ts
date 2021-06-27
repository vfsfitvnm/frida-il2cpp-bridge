import { Api } from "../api";
import { injectToIl2Cpp, since } from "../decorators";

@injectToIl2Cpp("GC")
class Il2CppGC {
    static choose(klass: Il2Cpp.Class): Il2Cpp.Object[] {
        const matches: Il2Cpp.Object[] = [];

        const callback = (objects: NativePointer, size: number, _: NativePointer) => {
            for (let i = 0; i < size; i++) {
                matches.push(new Il2Cpp.Object(objects.add(i * Process.pointerSize).readPointer()));
            }
        };

        const chooseCallback = new NativeCallback(callback, "void", ["pointer", "int", "pointer"]);
        const onWorld = new NativeCallback(() => {}, "void", []);

        const state = Api._livenessCalculationBegin(klass.handle, 0, chooseCallback, NULL, onWorld, onWorld);
        Api._livenessCalculationFromStatics(state);
        Api._livenessCalculationEnd(state);

        return matches;
    }

    static collect(generation: 0 | 1 | 2): void {
        Api._gcCollect(generation < 0 ? 0 : generation > 2 ? 2 : generation);
    }

    @since("5.3.5")
    static collectALittle(): void {
        Api._gcCollectALittle();
    }

    @since("5.3.5")
    static disable(): void {
        Api._gcDisable();
    }

    @since("5.3.5")
    static enable(): void {
        Api._gcEnable();
    }

    @since("2018.3.0")
    static isDisabled(): boolean {
        return Api._gcIsDisabled();
    }
}
