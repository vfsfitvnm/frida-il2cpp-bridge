namespace Il2Cpp {
    export class Tracer {
        /** @internal */
        #state: Il2Cpp.Tracer.State = {
            depth: 0,
            buffer: [],
            history: new Set(),
            flush: () => {
                if (this.#state.depth == 0) {
                    const message = `\n${this.#state.buffer.join("\n")}\n`;

                    if (this.#verbose) {
                        inform(message);
                    } else {
                        const hash = cyrb53(message);
                        if (!this.#state.history.has(hash)) {
                            this.#state.history.add(hash);
                            inform(message);
                        }
                    }

                    this.#state.buffer.length = 0;
                }
            }
        };

        /** @internal */
        #threadId: number = Il2Cpp.mainThread.id;

        /** @internal */
        #verbose: boolean = false;

        /** @internal */
        #applier: Il2Cpp.Tracer.Apply;

        /** @internal */
        #targets: Il2Cpp.Method[] = [];

        /** @internal */
        #domain?: Il2Cpp.Domain;

        /** @internal */
        #assemblies?: Il2Cpp.Assembly[];

        /** @internal */
        #classes?: Il2Cpp.Class[];

        /** @internal */
        #methods?: Il2Cpp.Method[];

        /** @internal */
        #assemblyFilter?: (assembly: Il2Cpp.Assembly) => boolean;

        /** @internal */
        #classFilter?: (klass: Il2Cpp.Class) => boolean;

        /** @internal */
        #methodFilter?: (method: Il2Cpp.Method) => boolean;

        /** @internal */
        #parameterFilter?: (parameter: Il2Cpp.Parameter) => boolean;

        constructor(applier: Il2Cpp.Tracer.Apply) {
            this.#applier = applier;
        }

        /** */
        thread(thread: Il2Cpp.Thread): Pick<Il2Cpp.Tracer, "verbose"> & Il2Cpp.Tracer.ChooseTargets {
            this.#threadId = thread.id;
            return this;
        }

        /** Determines whether print duplicate logs. */
        verbose(value: boolean): Il2Cpp.Tracer.ChooseTargets {
            this.#verbose = value;
            return this;
        }

        /** Sets the application domain as the place where to find the target methods. */
        domain(): Il2Cpp.Tracer.FilterAssemblies {
            this.#domain = Il2Cpp.domain;
            return this;
        }

        /** Sets the passed `assemblies` as the place where to find the target methods. */
        assemblies(...assemblies: Il2Cpp.Assembly[]): Il2Cpp.Tracer.FilterClasses {
            this.#assemblies = assemblies;
            return this;
        }

        /** Sets the passed `classes` as the place where to find the target methods. */
        classes(...classes: Il2Cpp.Class[]): Il2Cpp.Tracer.FilterMethods {
            this.#classes = classes;
            return this;
        }

        /** Sets the passed `methods` as the target methods. */
        methods(...methods: Il2Cpp.Method[]): Il2Cpp.Tracer.FilterParameters {
            this.#methods = methods;
            return this;
        }

        /** Filters the assemblies where to find the target methods. */
        filterAssemblies(filter: (assembly: Il2Cpp.Assembly) => boolean): Il2Cpp.Tracer.FilterClasses {
            this.#assemblyFilter = filter;
            return this;
        }

        /** Filters the classes where to find the target methods. */
        filterClasses(filter: (klass: Il2Cpp.Class) => boolean): Il2Cpp.Tracer.FilterMethods {
            this.#classFilter = filter;
            return this;
        }

        /** Filters the target methods. */
        filterMethods(filter: (method: Il2Cpp.Method) => boolean): Il2Cpp.Tracer.FilterParameters {
            this.#methodFilter = filter;
            return this;
        }

        /** Filters the target methods. */
        filterParameters(filter: (parameter: Il2Cpp.Parameter) => boolean): Pick<Il2Cpp.Tracer, "and"> {
            this.#parameterFilter = filter;
            return this;
        }

        /** Commits the current changes by finding the target methods. */
        and(): Il2Cpp.Tracer.ChooseTargets & Pick<Il2Cpp.Tracer, "attach"> {
            const filterMethod = (method: Il2Cpp.Method): void => {
                if (this.#parameterFilter == undefined) {
                    this.#targets.push(method);
                    return;
                }

                for (const parameter of method.parameters) {
                    if (this.#parameterFilter(parameter)) {
                        this.#targets.push(method);
                        break;
                    }
                }
            };

            const filterMethods = (values: Iterable<Il2Cpp.Method>): void => {
                for (const method of values) {
                    filterMethod(method);
                }
            };

            const filterClass = (klass: Il2Cpp.Class): void => {
                if (this.#methodFilter == undefined) {
                    filterMethods(klass.methods);
                    return;
                }

                for (const method of klass.methods) {
                    if (this.#methodFilter(method)) {
                        filterMethod(method);
                    }
                }
            };

            const filterClasses = (values: Iterable<Il2Cpp.Class>): void => {
                for (const klass of values) {
                    filterClass(klass);
                }
            };

            const filterAssembly = (assembly: Il2Cpp.Assembly): void => {
                if (this.#classFilter == undefined) {
                    filterClasses(assembly.image.classes);
                    return;
                }

                for (const klass of assembly.image.classes) {
                    if (this.#classFilter(klass)) {
                        filterClass(klass);
                    }
                }
            };

            const filterAssemblies = (assemblies: Iterable<Il2Cpp.Assembly>): void => {
                for (const assembly of assemblies) {
                    filterAssembly(assembly);
                }
            };

            const filterDomain = (domain: Il2Cpp.Domain): void => {
                if (this.#assemblyFilter == undefined) {
                    filterAssemblies(domain.assemblies);
                    return;
                }

                for (const assembly of domain.assemblies) {
                    if (this.#assemblyFilter(assembly)) {
                        filterAssembly(assembly);
                    }
                }
            };

            this.#methods
                ? filterMethods(this.#methods)
                : this.#classes
                ? filterClasses(this.#classes)
                : this.#assemblies
                ? filterAssemblies(this.#assemblies)
                : this.#domain
                ? filterDomain(this.#domain)
                : undefined;

            this.#assemblies = undefined;
            this.#classes = undefined;
            this.#methods = undefined;
            this.#assemblyFilter = undefined;
            this.#classFilter = undefined;
            this.#methodFilter = undefined;
            this.#parameterFilter = undefined;

            return this;
        }

        /** Starts tracing. */
        attach(): void {
            for (const target of this.#targets) {
                if (!target.virtualAddress.isNull()) {
                    try {
                        this.#applier(target, this.#state, this.#threadId);
                    } catch (e: any) {
                        switch (e.message) {
                            case /unable to intercept function at \w+; please file a bug/.exec(e.message)?.input:
                            case "already replaced this function":
                                break;
                            default:
                                throw e;
                        }
                    }
                }
            }
        }
    }

    export declare namespace Tracer {
        export type Configure = Pick<Il2Cpp.Tracer, "thread" | "verbose"> & Il2Cpp.Tracer.ChooseTargets;

        export type ChooseTargets = Pick<Il2Cpp.Tracer, "domain" | "assemblies" | "classes" | "methods">;

        export type FilterAssemblies = FilterClasses & Pick<Il2Cpp.Tracer, "filterAssemblies">;

        export type FilterClasses = FilterMethods & Pick<Il2Cpp.Tracer, "filterClasses">;

        export type FilterMethods = FilterParameters & Pick<Il2Cpp.Tracer, "filterMethods">;

        export type FilterParameters = Pick<Il2Cpp.Tracer, "and"> & Pick<Il2Cpp.Tracer, "filterParameters">;

        export interface State {
            depth: number;
            buffer: string[];
            history: Set<number>;
            flush: () => void;
        }

        export type Apply = (method: Il2Cpp.Method, state: Il2Cpp.Tracer.State, threadId: number) => void;
    }

    /** */
    export function trace(parameters: boolean = false): Il2Cpp.Tracer.Configure {
        const applier = (): Il2Cpp.Tracer.Apply => (method, state, threadId) => {
            const paddedVirtualAddress = method.relativeVirtualAddress.toString(16).padStart(8, "0");

            Interceptor.attach(method.virtualAddress, {
                onEnter() {
                    if (this.threadId == threadId) {
                        // prettier-ignore
                        state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(state.depth++)}┌─\x1b[35m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m`);
                    }
                },
                onLeave() {
                    if (this.threadId == threadId) {
                        // prettier-ignore
                        state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(--state.depth)}└─\x1b[33m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m`);
                        state.flush();
                    }
                }
            });
        };

        const applierWithParameters = (): Il2Cpp.Tracer.Apply => (method, state, threadId) => {
            const paddedVirtualAddress = method.relativeVirtualAddress.toString(16).padStart(8, "0");

            const startIndex = +!method.isStatic | +Il2Cpp.unityVersionIsBelow201830;

            const callback = function (this: CallbackContext | InvocationContext, ...args: any[]) {
                if ((this as InvocationContext).threadId == threadId) {
                    const thisParameter = method.isStatic ? undefined : new Il2Cpp.Parameter("this", -1, method.class.type);
                    const parameters = thisParameter ? [thisParameter].concat(method.parameters) : method.parameters;

                    // prettier-ignore
                    state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(state.depth++)}┌─\x1b[35m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m(${parameters.map(e => `\x1b[32m${e.name}\x1b[0m = \x1b[31m${fromFridaValue(args[e.position + startIndex], e.type)}\x1b[0m`).join(", ")})`);
                }

                const returnValue = method.nativeFunction(...args);

                if ((this as InvocationContext).threadId == threadId) {
                    // prettier-ignore
                    state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(--state.depth)}└─\x1b[33m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m${returnValue == undefined ? "" : ` = \x1b[36m${fromFridaValue(returnValue, method.returnType)}`}\x1b[0m`);
                    state.flush();
                }

                return returnValue;
            };

            method.revert();
            const nativeCallback = new NativeCallback(callback, method.returnType.fridaAlias, method.fridaSignature);
            Interceptor.replace(method.virtualAddress, nativeCallback);
        };

        return new Il2Cpp.Tracer(parameters ? applierWithParameters() : applier());
    }

    /** */
    export function backtrace(mode?: Backtracer): Il2Cpp.Tracer.Configure {
        const methods = Il2Cpp.domain.assemblies
            .flatMap(_ => _.image.classes.flatMap(_ => _.methods.filter(_ => !_.virtualAddress.isNull())))
            .sort((_, __) => _.virtualAddress.compare(__.virtualAddress));

        const searchInsert = (target: NativePointer): Il2Cpp.Method => {
            let left = 0;
            let right = methods.length - 1;

            while (left <= right) {
                const pivot = Math.floor((left + right) / 2);
                const comparison = methods[pivot].virtualAddress.compare(target);

                if (comparison == 0) {
                    return methods[pivot];
                } else if (comparison > 0) {
                    right = pivot - 1;
                } else {
                    left = pivot + 1;
                }
            }
            return methods[right];
        };

        const applier = (): Il2Cpp.Tracer.Apply => (method, state, threadId) => {
            Interceptor.attach(method.virtualAddress, function () {
                if (this.threadId == threadId) {
                    const handles = globalThis.Thread.backtrace(this.context, mode);
                    handles.unshift(method.virtualAddress);

                    for (const handle of handles) {
                        if (handle.compare(Il2Cpp.module.base) > 0 && handle.compare(Il2Cpp.module.base.add(Il2Cpp.module.size)) < 0) {
                            const method = searchInsert(handle);

                            if (method) {
                                const offset = handle.sub(method.virtualAddress);

                                if (offset.compare(0xfff) < 0) {
                                    // prettier-ignore
                                    state.buffer.push(`\x1b[2m0x${method.relativeVirtualAddress.toString(16).padStart(8, "0")}\x1b[0m\x1b[2m+0x${offset.toString(16).padStart(3, `0`)}\x1b[0m ${method.class.type.name}::\x1b[1m${method.name}\x1b[0m`);
                                }
                            }
                        }
                    }

                    state.flush();
                }
            });
        };

        return new Il2Cpp.Tracer(applier());
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
}
