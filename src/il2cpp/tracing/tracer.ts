namespace Il2Cpp {
    export class Tracer extends Il2Cpp.AbstractTracer {
        /** @internal */
        private withParameters: boolean = false;

        /** @internal */
        private isVerbose: boolean = true;

        /** Determines whether print parameters. */
        parameters(value: boolean): Pick<Il2Cpp.Tracer, "verbose"> {
            this.withParameters = value;
            return this;
        }

        /** Determines whether print duplicate logs. */
        verbose(value: boolean): Il2Cpp.AbstractTracer.ChooseTargets {
            this.isVerbose = value;
            return this;
        }

        attach(): void {
            const tracer = this;
            const mainThreadId = Il2Cpp.mainThread.id;

            for (const target of this.targets) {
                if (target.virtualAddress.isNull()) {
                    continue;
                }

                const offset = `\x1b[2m0x${target.relativeVirtualAddress.toString(16).padStart(8, `0`)}\x1b[0m`;
                const fullName = `${target.class.type.name}::\x1b[1m${target.name}\x1b[0m`;

                if (!this.withParameters) {
                    try {
                        Interceptor.attach(target.virtualAddress, {
                            onEnter() {
                                if (this.threadId == mainThreadId) {
                                    tracer.events.buffer.push(`${offset} ${`│ `.repeat(tracer.events.depth++)}┌─\x1b[35m${fullName}\x1b[0m`);
                                }
                            },
                            onLeave() {
                                if (this.threadId == mainThreadId) {
                                    tracer.events.buffer.push(`${offset} ${`│ `.repeat(--tracer.events.depth)}└─\x1b[33m${fullName}\x1b[0m`);
                                    tracer.maybeFlush(!tracer.isVerbose);
                                }
                            }
                        });
                    } catch (e: any) {}
                } else {
                    const startIndex = +!target.isStatic | +Il2Cpp.unityVersionIsBelow201830;

                    const callback = function (this: CallbackContext | InvocationContext, ...args: any[]) {
                        if ((this as InvocationContext).threadId == mainThreadId) {
                            const thisParameter = target.isStatic ? undefined : new Il2Cpp.Parameter("this", -1, target.class.type);
                            const parameters = thisParameter ? [thisParameter].concat(target.parameters) : target.parameters;

                            tracer.events.buffer.push(`\
${offset} ${`│ `.repeat(tracer.events.depth++)}┌─\x1b[35m${fullName}\x1b[0m(\
${parameters.map(e => `\x1b[32m${e.name}\x1b[0m = \x1b[31m${fromFridaValue(args[e.position + startIndex], e.type)}\x1b[0m`).join(`, `)});`);
                        }

                        const returnValue = target.nativeFunction(...args);

                        if ((this as InvocationContext).threadId == mainThreadId) {
                            tracer.events.buffer.push(`\
${offset} ${`│ `.repeat(--tracer.events.depth)}└─\x1b[33m${fullName}\x1b[0m\
${returnValue == undefined ? `` : ` = \x1b[36m${fromFridaValue(returnValue, target.returnType)}`}\x1b[0m;`);

                            tracer.maybeFlush(!tracer.isVerbose);
                        }

                        return returnValue;
                    };

                    try {
                        target.revert();
                        const nativeCallback = new NativeCallback(callback, target.returnType.fridaAlias, target.fridaSignature);
                        Interceptor.replace(target.virtualAddress, nativeCallback);
                    } catch (e: any) {}
                }
            }
        }
    }

    /** Creates a new `Il2Cpp.Tracer` instance. */
    export function trace(): Pick<Il2Cpp.Tracer, "parameters"> {
        return new Il2Cpp.Tracer();
    }
}
