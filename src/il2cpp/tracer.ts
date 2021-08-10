import { inform } from "../utils/console";
import { formatNativePointer } from "../utils/utils";
import kleur from "kleur";

/** Tracing utilities. */
class Il2CppTracer {
    protected constructor() {}

    /** Reports method invocations, input arguments, returns and return values. */
    static fullWithValuesTrace(...targets: Il2Cpp.Tracer.Targets): void {
        let counter = 0;

        this.trace((method: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
            const at = kleur.white(formatNativePointer(method.relativeVirtualAddress));
            const sign = `${method.class.type.name}.${kleur.bold(method.name)}`;
            const _parametersInfo = Object.values(method.parameters);

            return {
                onEnter(...parameters: Il2Cpp.Parameter.Type[]): void {
                    const parametersInfo = parameters
                        .map((value: Il2Cpp.Parameter.Type, index: number) => {
                            const _param = _parametersInfo[index];
                            return `${kleur.blue(_param.type.name)} ${kleur.yellow(_param.name)} = ${kleur.cyan(value + "")}`;
                        })
                        .join(", ");

                    inform(`${at} ${"│ ".repeat(counter)}┌─${kleur.red(sign)}${kleur.yellow("(")}${parametersInfo}${kleur.yellow(")")}`);
                    counter += 1;
                },
                onLeave(returnValue: Il2Cpp.Method.ReturnType): void {
                    counter -= 1;
                    inform(
                        `${at} ${"│ ".repeat(counter)}└─${kleur.green(sign)} ${kleur.magenta(method.returnType.name)} = ${kleur.cyan(
                            returnValue + ""
                        )}`
                    );
                    if (counter == 0) {
                        console.log();
                    }
                }
            };
        }, ...targets);
    }

    /** Reports method invocations and returns. */
    static fullTrace(...targets: Il2Cpp.Tracer.Targets): void {
        let counter = 0;

        this.trace((method: Il2Cpp.Method) => {
            const at = kleur.white(formatNativePointer(method.relativeVirtualAddress));
            const sign = `${method.class.type.name}.${kleur.bold(method.name)}`;

            return {
                onEnter() {
                    inform(`${at} ${"│ ".repeat(counter)}┌─${kleur.red(sign)}`);
                    counter += 1;
                },
                onLeave() {
                    counter -= 1;
                    inform(`${at} ${"│ ".repeat(counter)}└─${kleur.green(sign)}`);

                    if (counter == 0) {
                        console.log();
                    }
                }
            };
        }, ...targets);
    }

    /** Reports method invocations. */
    static simpleTrace(...targets: Il2Cpp.Tracer.Targets): void {
        this.trace((method: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
            const at = kleur.white(formatNativePointer(method.relativeVirtualAddress));
            const sign = `${method.class.type.name}.${kleur.bold(method.name)}`;
            return {
                onEnter() {
                    inform(`${at} ${sign}`);
                }
            };
        }, ...targets);
    }

    /** Traces the given methods. */
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

Il2Cpp.Tracer = Il2CppTracer;

declare global {
    namespace Il2Cpp {
        class Tracer extends Il2CppTracer {}

        namespace Tracer {
            type Callbacks = RequireAtLeastOne<{
                onEnter?: (...parameters: Il2Cpp.Parameter.Type[]) => void;
                onLeave?: (returnValue: Il2Cpp.Method.ReturnType) => void;
            }>;

            type Targets = (Il2Cpp.Method | Il2Cpp.Class)[];
        }
    }
}
