import { inform } from "../../utils/console.js";
import { fromFridaValue } from "../utils.js";
import { AbstractTracer } from "./abstract-tracer.js";

/** Tracing utilities. */
class Il2CppTracer extends AbstractTracer {
    #mode: Mode = Mode.Default;

    detailed(): Pick<Il2Cpp.Tracer, "domain" | "assemblies" | "classes" | "methods"> {
        this.#mode = Mode.Detailed;
        return this;
    }

    attach(): void {
        let count = 0;

        for (const target of this.targets) {
            if (target.virtualAddress.isNull()) {
                continue;
            }

            const offset = `\x1b[2m0x${target.relativeVirtualAddress.toString(16).padStart(8, `0`)}\x1b[0m`;
            const fullName = `${target.class.type.name}.\x1b[1m${target.name}\x1b[0m`;

            switch (this.#mode) {
                case Mode.Default: {
                    try {
                        Interceptor.attach(target.virtualAddress, {
                            onEnter: () => {
                                if (this.startTargets.length > 0 && !this.startTargets.includes(target.handle.toString()) && count==0) return;
                                inform(`${offset} ${`│ `.repeat(count++)}┌─\x1b[35m${fullName}\x1b[0m`)
                            },
                            onLeave: () => {
                                if (this.startTargets.length > 0 && count <= 0) return;
                                inform(`${offset} ${`│ `.repeat(--count)}└─\x1b[33m${fullName}\x1b[0m${count == 0 ? `\n` : ``}`)
                            }
                        });
                    } catch (e: any) {}
                    break;
                }
                case Mode.Detailed: {
                    const startIndex = +!target.isStatic | +Il2Cpp.unityVersionIsBelow201830;

                    const callback = (...args: any[]): any => {
                        if (!(this.startTargets.length > 0 && !this.startTargets.includes(target.handle.toString()) && count==0)) {
                            const thisParameter = target.isStatic ? undefined : new Il2Cpp.Parameter("this", -1, target.class.type);
                            const parameters = thisParameter ? [thisParameter].concat(target.parameters) : target.parameters;

                            inform(`\
${offset} ${`│ `.repeat(count++)}┌─\x1b[35m${fullName}\x1b[0m(\
${parameters.map(e => `\x1b[32m${e.name}\x1b[0m = \x1b[31m${fromFridaValue(args[e.position + startIndex], e.type)}\x1b[0m`).join(`, `)});`);
                        }

                        const returnValue = target.nativeFunction(...args);

                        if (!(this.startTargets.length > 0 && !this.startTargets.includes(target.handle.toString()) && count==0)) {
                            inform(`\
${offset} ${`│ `.repeat(--count)}└─\x1b[33m${fullName}\x1b[0m\
${returnValue == undefined ? `` : ` = \x1b[36m${fromFridaValue(returnValue, target.returnType)}`}\x1b[0m;`);
                        }

                        return returnValue;
                    };

                    try {
                        target.revert();
                        const nativeCallback = new NativeCallback(callback, target.returnType.fridaAlias, target.fridaSignature);
                        Interceptor.replace(target.virtualAddress, nativeCallback);
                    } catch (e: any) {}
                    break;
                }
            }
        }
    }
}

const enum Mode {
    Default,
    Detailed
}

Il2Cpp.Tracer = Il2CppTracer;

declare global {
    namespace Il2Cpp {
        class Tracer extends Il2CppTracer {}
    }
}
