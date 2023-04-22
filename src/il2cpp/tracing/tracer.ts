namespace Il2Cpp {
    export class Tracer extends AbstractTracer {
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
                                onEnter: () => inform(`${offset} ${`│ `.repeat(count++)}┌─\x1b[35m${fullName}\x1b[0m`),
                                onLeave: () => inform(`${offset} ${`│ `.repeat(--count)}└─\x1b[33m${fullName}\x1b[0m${count == 0 ? `\n` : ``}`)
                            });
                        } catch (e: any) {}
                        break;
                    }
                    case Mode.Detailed: {
                        const startIndex = +!target.isStatic | +Il2Cpp.unityVersionIsBelow201830;

                        const callback = (...args: any[]): any => {
                            const thisParameter = target.isStatic ? undefined : new Il2Cpp.Parameter("this", -1, target.class.type);
                            const parameters = thisParameter ? [thisParameter].concat(target.parameters) : target.parameters;

                            inform(`\
${offset} ${`│ `.repeat(count++)}┌─\x1b[35m${fullName}\x1b[0m(\
${parameters.map(e => `\x1b[32m${e.name}\x1b[0m = \x1b[31m${fromFridaValue(args[e.position + startIndex], e.type)}\x1b[0m`).join(`, `)});`);

                            const returnValue = target.nativeFunction(...args);

                            inform(`\
${offset} ${`│ `.repeat(--count)}└─\x1b[33m${fullName}\x1b[0m\
${returnValue == undefined ? `` : ` = \x1b[36m${fromFridaValue(returnValue, target.returnType)}`}\x1b[0m;`);

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

    /** Creates a new `Il2Cpp.Tracer` instance. */
    export function trace(): Pick<Il2Cpp.Tracer, "detailed" | "domain" | "assemblies" | "classes" | "methods"> {
        return new Il2Cpp.Tracer();
    }
}
