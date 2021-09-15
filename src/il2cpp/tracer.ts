import kleur from "kleur";
import { inform } from "../utils/console";
import { formatNativePointer } from "../utils/utils";

/** Tracing utilities. */
class Il2CppTracer {
    readonly targets: Il2Cpp.Method[] = [];

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

    /** @internal */
    #generator?: (method: Il2Cpp.Method) => Il2Cpp.Tracer.Callbacks;

    domain(): FilterAssemblies {
        return this;
    }

    assemblies(...assemblies: NonEmptyArray<Il2Cpp.Assembly>): FilterClasses {
        this.#assemblies = assemblies;
        return this;
    }

    classes(...classes: NonEmptyArray<Il2Cpp.Class>): FilterMethods {
        this.#classes = classes;
        return this;
    }

    methods(...methods: NonEmptyArray<Il2Cpp.Method>): FilterParameters {
        this.#methods = methods;
        return this;
    }

    filterAssemblies(filter: (assembly: Il2Cpp.Assembly) => boolean): FilterClasses {
        this.#assemblyFilter = filter;
        return this;
    }

    filterClasses(filter: (klass: Il2Cpp.Class) => boolean): FilterMethods {
        this.#classFilter = filter;
        return this;
    }

    filterMethods(filter: (method: Il2Cpp.Method) => boolean): FilterParameters {
        this.#methodFilter = filter;
        return this;
    }

    filterParameters(filter: (parameter: Il2Cpp.Parameter) => boolean): Pick<Il2Cpp.Tracer, "commit"> {
        this.#parameterFilter = filter;
        return this;
    }

    commit(): ReturnType<typeof Il2Cpp["trace"]> & Pick<Il2Cpp.Tracer, "targets" | "simple" | "full" | "detailed" | "special"> {
        const filterMethod = (method: Il2Cpp.Method): void => {
            if (this.#parameterFilter == undefined) {
                this.targets.push(method);
                return;
            }

            for (const parameter of method.parameters) {
                if (this.#parameterFilter(parameter)) {
                    this.targets.push(method);
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

        const filterDomain = (domain: typeof Il2Cpp.Domain): void => {
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
            : filterDomain(Il2Cpp.Domain);

        this.#assemblies = undefined;
        this.#classes = undefined;
        this.#methods = undefined;
        this.#assemblyFilter = undefined;
        this.#classFilter = undefined;
        this.#methodFilter = undefined;
        this.#parameterFilter = undefined;
        this.#generator = undefined;

        return this;
    }

    /** Reports method invocations. */
    simple(): Pick<Il2Cpp.Tracer, "build"> {
        this.#generator = (target: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
            const at = kleur.white(formatNativePointer(target.relativeVirtualAddress));
            const sign = `${target.class.type.name}.${kleur.bold(target.name)}`;

            return {
                onEnter() {
                    inform(`${at} ${sign}`);
                }
            };
        };

        return this;
    }

    /** Reports method invocations and returns. */
    full(): Pick<Il2Cpp.Tracer, "build"> {
        let counter = 0;

        this.#generator = (target: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
            const at = kleur.white(formatNativePointer(target.relativeVirtualAddress));
            const sign = `${target.class.type.name}.${kleur.bold(target.name)}`;

            return {
                onEnter() {
                    inform(`${at} ${"│ ".repeat(counter)}┌─${kleur.red(sign)}`);
                    counter += 1;
                },
                onLeave() {
                    counter -= 1;
                    inform(`${at} ${"│ ".repeat(counter)}└─${kleur.green(sign)}${counter == 0 ? "\n" : ""}`);
                }
            };
        };

        return this;
    }

    /** Reports method invocations, input arguments, returns and return values. */
    detailed(): Pick<Il2Cpp.Tracer, "build"> {
        let counter = 0;

        this.#generator = (target: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
            const at = kleur.white(formatNativePointer(target.relativeVirtualAddress));
            const sign = `${target.class.type.name}.${kleur.bold(target.name)}`;
            const parametersInfo = Object.values(target.parameters);

            return {
                onEnter(...parameters: Il2Cpp.Parameter.Type[]): void {
                    const thisText = target.isStatic
                        ? ""
                        : `${kleur.yellow("this")} = ${kleur.cyan(this + "")}${parameters.length > 0 ? ", " : ""}`;
                    const parametersText = parametersInfo
                        .map(({ type, name }, index) => {
                            return `${kleur.blue(type.name)} ${kleur.yellow(name)} = ${kleur.cyan(parameters[index] + "")}`;
                        })
                        .join(", ");

                    inform(
                        `${at} ${"│ ".repeat(counter)}┌─${kleur.red(sign)}${kleur.yellow("(")}${thisText}${parametersText}${kleur.yellow(
                            ")"
                        )}`
                    );
                    counter += 1;
                },
                onLeave(returnValue: Il2Cpp.Method.ReturnType): void {
                    counter -= 1;
                    inform(
                        `${at} ${"│ ".repeat(counter)}└─${kleur.green(sign)} ${kleur.magenta(target.returnType.name)} = ${kleur.cyan(
                            returnValue + ""
                        )}${counter == 0 ? "\n" : ""}`
                    );
                }
            };
        };

        return this;
    }

    /** Custom behaviour. */
    special(generator: (target: Il2Cpp.Method) => Il2Cpp.Tracer.Callbacks): Pick<Il2Cpp.Tracer, "build"> {
        this.#generator = generator;
        return this;
    }

    build(): void {
        for (const target of this.targets) {
            if (target.virtualAddress.isNull()) {
                continue;
            }

            const { onEnter, onLeave } = this.#generator!(target);

            target.implementation = function (...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Method.ReturnType {
                onEnter?.apply(this, parameters);

                const returnValue = (this instanceof Il2Cpp.Object ? target.withHolder(this) : target).invoke(...parameters);

                onLeave?.call(this, returnValue);

                return returnValue;
            };
        }
    }
}

type NonEmptyArray<T> = [T, ...T[]];

type FilterAssemblies = FilterClasses & Pick<Il2Cpp.Tracer, "filterAssemblies">;

type FilterClasses = FilterMethods & Pick<Il2Cpp.Tracer, "filterClasses">;

type FilterMethods = FilterParameters & Pick<Il2Cpp.Tracer, "filterMethods">;

type FilterParameters = Pick<Il2Cpp.Tracer, "commit"> & Pick<Il2Cpp.Tracer, "filterParameters">;

Il2Cpp.Tracer = Il2CppTracer;

declare global {
    namespace Il2Cpp {
        class Tracer extends Il2CppTracer {}

        namespace Tracer {
            type Callbacks = {
                onEnter?: (this: Il2Cpp.Class | Il2Cpp.Object, ...parameters: Il2Cpp.Parameter.Type[]) => void;
                onLeave?: (this: Il2Cpp.Class | Il2Cpp.Object, returnValue: Il2Cpp.Method.ReturnType) => void;
            };
        }
    }
}
