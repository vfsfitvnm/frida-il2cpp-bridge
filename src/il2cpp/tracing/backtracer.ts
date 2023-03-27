import { inform } from "../../utils/console.js";
import { AbstractTracer } from "./abstract-tracer.js";

/** Backtracing utilities. */
class Il2CppBacktracer extends AbstractTracer {
    #flags: Flags = Flags.Empty;

    readonly #methods = Il2Cpp.Domain.assemblies
        .flatMap(_ => _.image.classes.flatMap(_ => _.methods.filter(_ => !_.virtualAddress.isNull())))
        .sort((_, __) => _.virtualAddress.compare(__.virtualAddress));

    accurate(): Pick<Il2Cpp.Backtracer, "verbose" | "distinct"> {
        this.#flags |= Flags.Accurate;
        return this;
    }

    fuzzy(): ReturnType<Il2Cpp.Backtracer["accurate"]> {
        return this;
    }

    verbose(): Pick<Il2Cpp.Backtracer, "clean" | "dirty"> {
        return this;
    }

    distinct(): ReturnType<Il2Cpp.Backtracer["verbose"]> {
        this.#flags |= Flags.Distinct;
        return this;
    }

    dirty(): Pick<Il2Cpp.Backtracer, "domain" | "assemblies" | "classes" | "methods"> {
        return this;
    }

    clean(): ReturnType<Il2Cpp.Backtracer["dirty"]> {
        this.#flags |= Flags.Clean;
        return this;
    }

    attach(): void {
        const backtracer = this;
        const history = backtracer.#flags & Flags.Distinct ? new Set<string>() : undefined;

        for (const target of this.targets) {
            if (target.virtualAddress.isNull()) {
                continue;
            }

            try {
                Interceptor.attach(target.virtualAddress, function () {
                    let backtrace = Thread.backtrace(
                        this.context,
                        backtracer.#flags & Flags.Accurate ? Backtracer.ACCURATE : Backtracer.FUZZY
                    ).reverse();

                    backtrace.push(target.virtualAddress);

                    if (backtracer.#flags & Flags.Distinct) {
                        const key = backtrace.map(_ => _.toString()).join("");

                        if (history?.has(key)) {
                            return;
                        }

                        history?.add(key);
                    }

                    let i = 0;

                    for (const address of backtrace) {
                        const method =
                            address >= Il2Cpp.module.base && address < Il2Cpp.module.base.add(Il2Cpp.module.size)
                                ? backtracer.#searchInsert(address)
                                : undefined;

                        const decoration = i == 0 ? "" : `${" ".repeat((i - 1) * 2)}└─`;

                        if (method != undefined) {
                            const offset = address.sub(method.virtualAddress);

                            if (backtracer.#flags & Flags.Clean && address.sub(method.virtualAddress).compare(0xfff) > 0) {
                                continue;
                            }

                            inform(`\
\x1b[2m\
0x${method.relativeVirtualAddress.toString(16).padStart(8, `0`)}\
+0x${offset.toString(16).padStart(backtracer.#flags & Flags.Clean ? 3 : 8, `0`)}\
\x1b[0m\
 ${decoration}\
${method.class.type.name}.\x1b[1m${method.name}\x1b[0m`);
                        } else {
                            if (backtracer.#flags & Flags.Clean) {
                                continue;
                            }

                            const debugSymbol = DebugSymbol.fromAddress(address);
                            inform(`\
\x1b[2m\
0x${debugSymbol.address.toString(16).padStart(19, `0`)}\
\x1b[0m\
 ${decoration}\
${debugSymbol.moduleName}`);
                        }

                        i++;
                    }
                });
            } catch (e: any) {}
        }
    }

    #searchInsert(target: NativePointer): Il2Cpp.Method {
        let left = 0;
        let right = this.#methods.length - 1;

        while (left <= right) {
            const pivot = Math.floor((left + right) / 2);
            const comparison = this.#methods[pivot].virtualAddress.compare(target);

            if (comparison == 0) {
                return this.#methods[pivot];
            } else if (comparison > 0) {
                right = pivot - 1;
            } else {
                left = pivot + 1;
            }
        }
        return this.#methods[right];
    }
}

const enum Flags {
    Empty = 0,
    Accurate = 1 << 0,
    Distinct = 1 << 1,
    Clean = 1 << 2
}

Il2Cpp.Backtracer = Il2CppBacktracer;

declare global {
    namespace Il2Cpp {
        class Backtracer extends Il2CppBacktracer {}
    }
}
