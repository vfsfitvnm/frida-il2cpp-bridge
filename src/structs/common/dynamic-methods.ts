namespace Il2Cpp {
    export type DynamicMethods = {
        [K in Exclude<string, ["constructor" | "#invokeMethod"]>]: (...parameters: (Il2Cpp.Parameter.TypeValue | Il2Cpp.Parameter.Type)[]) => any;
    };

    export class DynamicMethodsLookup {
        constructor(public readonly target: Il2Cpp.ObjectLike | Il2Cpp.Class, isStatic: boolean) {
            this.class.methods
                .filter(m => !m.isStatic === !isStatic)
                .forEach(m => {
                    globalThis.Object.defineProperty(this, m.name, {
                        value: this.#invokeMethod.bind(this, m.name),
                        enumerable: true,
                        configurable: true
                    });
                });
        }

        get class(): Il2Cpp.Class {
            return this.target instanceof Il2Cpp.ObjectLike ? this.target.class : this.target;
        }

        #invokeMethod<T extends Il2Cpp.Method.ReturnType>(name: string, ...parameters: (Il2Cpp.Parameter.TypeValue | Il2Cpp.Parameter.Type)[]): T {
            const paramTypes = parameters.map(p => (Il2Cpp.Parameter.isTypeValue(p) ? p.type : Il2Cpp.Type.fromValue(p)));
            const paramValues = parameters.map(p => (Il2Cpp.Parameter.isTypeValue(p) ? p.value : p));

            return this.target.methodWithSignature<T>(name, ...paramTypes).invoke(...paramValues);
        }

        static from(target: Il2Cpp.ObjectLike | Il2Cpp.Class, isStatic: boolean): Il2Cpp.DynamicMethods {
            return new DynamicMethodsLookup(target, isStatic) as unknown as Il2Cpp.DynamicMethods;
        }
    }
}
