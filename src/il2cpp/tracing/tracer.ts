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
            const mainThreadId = Il2Cpp.mainThread.id;
            const events = { depth: 0, buffer: [] as string[], history: new Set() };

            const maybeFlushEvents = () => {
                if (events.depth == 0) {
                    const message = `\n${events.buffer.join("\n")}\n`;

                    if (!this.isVerbose) {
                        const hash = cyrb53(message);
                        if (!events.history.has(hash)) {
                            events.history.add(hash);
                            inform(message);
                        }
                    } else {
                        inform(message);
                    }

                    events.buffer.length = 0;
                }
            };

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
                                    events.buffer.push(`${offset} ${`│ `.repeat(events.depth++)}┌─\x1b[35m${fullName}\x1b[0m`);
                                }
                            },
                            onLeave() {
                                if (this.threadId == mainThreadId) {
                                    events.buffer.push(`${offset} ${`│ `.repeat(--events.depth)}└─\x1b[33m${fullName}\x1b[0m`);
                                    maybeFlushEvents();
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

                            events.buffer.push(`\
${offset} ${`│ `.repeat(events.depth++)}┌─\x1b[35m${fullName}\x1b[0m(\
${parameters.map(e => `\x1b[32m${e.name}\x1b[0m = \x1b[31m${fromFridaValue(args[e.position + startIndex], e.type)}\x1b[0m`).join(`, `)});`);
                        }

                        const returnValue = target.nativeFunction(...args);

                        if ((this as InvocationContext).threadId == mainThreadId) {
                            events.buffer.push(`\
${offset} ${`│ `.repeat(--events.depth)}└─\x1b[33m${fullName}\x1b[0m\
${returnValue == undefined ? `` : ` = \x1b[36m${fromFridaValue(returnValue, target.returnType)}`}\x1b[0m;`);

                            maybeFlushEvents();
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

    /** https://stackoverflow.com/a/52171480/16885569 */
    function cyrb53(str: string): number {
        let h1 = 0xdeadbeef;
        let h2 = 0x41c6ce57;

        for (let i = 0, ch; i < str.length; i++) {
            ch = str.charCodeAt(i);
            h1 = Math.imul(h1 ^ ch, 2654435761);
            h2 = Math.imul(h2 ^ ch, 1597334677);
        }

        h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
        h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);

        h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
        h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);

        return 4294967296 * (2097151 & h2) + (h1 >>> 0);
    }

    /** Creates a new `Il2Cpp.Tracer` instance. */
    export function trace(): Pick<Il2Cpp.Tracer, "parameters"> {
        return new Il2Cpp.Tracer();
    }
}
