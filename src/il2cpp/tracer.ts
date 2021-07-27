import { injectToIl2Cpp } from "./decorators";

import { inform } from "../utils/console";
import { formatNativePointer } from "../utils/record";

@injectToIl2Cpp("Tracer")
class Tracer {
    static fullWithValuesTrace(...targets: Il2Cpp.Tracer.Targets): void {
        let counter = 0;

        this.trace((method: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
            const at = `\x1b[37m${formatNativePointer(method.relativeVirtualAddress)}\x1b[0m`;
            const sign = `${method.class.type.name}.\x1b[1m${method.name}\x1b[0m`;
            const _parametersInfo = Object.values(method.parameters);

            return {
                onEnter(...parameters: Il2Cpp.Parameter.Type[]): void {
                    const parametersInfo = parameters
                        .map((value: Il2Cpp.Parameter.Type, index: number) => {
                            return `\x1b[34m${_parametersInfo[index].type.name}\x1b[0m \x1b[33m${_parametersInfo[index].name}\x1b[0m = \x1b[36m${value}\x1b[0m`;
                        })
                        .join(", ");

                    inform(`${at} ${"│ ".repeat(counter)}┌─\x1b[31m${sign}\x1b[0m\x1b[33m(\x1b[0m${parametersInfo}\x1b[33m)\x1b[0m`);
                    counter += 1;
                },
                onLeave(returnValue: Il2Cpp.Method.ReturnType): void {
                    counter -= 1;
                    inform(
                        `${at} ${"│ ".repeat(counter)}└─\x1b[32m${sign}\x1b[0m \x1b[35m${
                            method.returnType.name
                        }\x1b[0m = \x1b[36m${returnValue}\x1b[0m`
                    );
                    if (counter == 0) {
                        console.log();
                    }
                }
            };
        }, ...targets);
    }

    static fullTrace(...targets: Il2Cpp.Tracer.Targets): void {
        let counter = 0;

        this.trace((method: Il2Cpp.Method) => {
            const at = `\x1b[37m${formatNativePointer(method.relativeVirtualAddress)}\x1b[0m`;
            const sign = `${method.class.type.name}.\x1b[1m${method.name}\x1b[0m`;

            return {
                onEnter() {
                    inform(`${at} ${"│ ".repeat(counter)}┌─\x1b[31m${sign}\x1b[0m`);
                    counter += 1;
                },
                onLeave() {
                    counter -= 1;
                    inform(`${at} ${"│ ".repeat(counter)}└─\x1b[32m${sign}\x1b[0m`);

                    if (counter == 0) {
                        console.log();
                    }
                }
            };
        }, ...targets);
    }

    static simpleTrace(...targets: Il2Cpp.Tracer.Targets): void {
        this.trace((method: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
            return {
                onEnter() {
                    inform(
                        `\x1b[37m${formatNativePointer(method.relativeVirtualAddress)}\x1b[0m ${method.class.type.name}.\x1b[1m${
                            method.name
                        }\x1b[0m`
                    );
                }
            };
        }, ...targets);
    }

    static trace(callbacksGenerator: (method: Il2Cpp.Method) => Il2Cpp.Tracer.Callbacks, ...targets: Il2Cpp.Tracer.Targets): void {
        function applyMethodImplementation(method: Il2Cpp.Method): void {
            if (method.virtualAddress.isNull()) {
                return;
            }

            const { onEnter, onLeave } = callbacksGenerator(method);

            method.implementation = function (...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Method.ReturnType {
                if (onEnter != undefined) {
                    onEnter(...parameters);
                }

                let returnValue: Il2Cpp.Method.ReturnType;
                if (this instanceof Il2Cpp.Object) {
                    returnValue = method.withHolder(this).invoke(...parameters);
                } else {
                    returnValue = method.invoke(...parameters);
                }

                if (onLeave != undefined) {
                    onLeave(returnValue);
                }

                return returnValue;
            };
        }

        for (const target of targets) {
            if (target instanceof Il2Cpp.Class) {
                for (const method of Object.values(target.methods)) {
                    applyMethodImplementation(method);
                }
            } else {
                applyMethodImplementation(target);
            }
        }
    }
}
