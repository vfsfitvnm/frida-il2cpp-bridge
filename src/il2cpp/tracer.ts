import kleur from "kleur";

import { inform } from "../utils/console";
import { formatNativePointer } from "../utils/utils";

/** Tracing utilities. */
class Il2CppTracer {
    protected constructor() {}

    /** @internal */
    private readonly targets: Il2Cpp.Method[] = [];

    /** @internal */
    private assemblies?: Il2Cpp.Assembly[];

    /** @internal */
    private classes?: Il2Cpp.Class[];

    /** @internal */
    private methods?: Il2Cpp.Method[];

    /** @internal */
    private assemblyFilter?: (assembly: Il2Cpp.Assembly) => boolean;

    /** @internal */
    private classFilter?: (klass: Il2Cpp.Class) => boolean;

    /** @internal */
    private methodFilter?: (method: Il2Cpp.Method) => boolean;

    /** @internal */
    private parameterFilter?: (parameter: Il2Cpp.Parameter) => boolean;

    /** @internal */
    private generator?: (method: Il2Cpp.Method) => Il2Cpp.Tracer.Callbacks;

    findInDomain(): FilterAssemblies {
        return this;
    }

    findInAssemblies(...assemblies: NonEmptyArray<Il2Cpp.Assembly>): FilterClasses {
        this.assemblies = assemblies;
        return this;
    }

    findInClasses(...classes: NonEmptyArray<Il2Cpp.Class>): FilterMethods {
        this.classes = classes;
        return this;
    }

    findInMethods(...methods: NonEmptyArray<Il2Cpp.Method>): FilterParameters {
        this.methods = methods;
        return this;
    }

    withAssemblyFilter(filter: (assembly: Il2Cpp.Assembly) => boolean): FilterClasses {
        this.assemblyFilter = filter;
        return this;
    }

    withClassFilter(filter: (klass: Il2Cpp.Class) => boolean): FilterMethods {
        this.classFilter = filter;
        return this;
    }

    withMethodFilter(filter: (method: Il2Cpp.Method) => boolean): FilterParameters {
        this.methodFilter = filter;
        return this;
    }

    withParameterFilter(filter: (parameter: Il2Cpp.Parameter) => boolean): Pick<Il2Cpp.Tracer, "commitAnd"> {
        this.parameterFilter = filter;
        return this;
    }

    commitAnd(): ReturnType<typeof Il2Cpp.Tracer["builder"]> & Pick<Il2Cpp.Tracer, "simply" | "fully" | "detailedly" | "specially"> {
        const filterMethod = (method: Il2Cpp.Method): void => {
            if (this.parameterFilter == undefined) {
                this.targets.push(method);
                return;
            }

            for (const parameter of method.parameters) {
                if (this.parameterFilter(parameter)) {
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
            if (this.methodFilter == undefined) {
                filterMethods(klass.methods);
                return;
            }

            for (const method of klass.methods) {
                if (this.methodFilter(method)) {
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
            if (this.classFilter == undefined) {
                filterClasses(assembly.image.classes);
                return;
            }

            for (const klass of assembly.image.classes) {
                if (this.classFilter(klass)) {
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
            if (this.assemblyFilter == undefined) {
                filterAssemblies(domain.assemblies);
                return;
            }

            for (const assembly of domain.assemblies) {
                if (this.assemblyFilter(assembly)) {
                    filterAssembly(assembly);
                }
            }
        };

        this.methods
            ? filterMethods(this.methods)
            : this.classes
            ? filterClasses(this.classes)
            : this.assemblies
            ? filterAssemblies(this.assemblies)
            : filterDomain(Il2Cpp.Domain);

        this.assemblies = undefined;
        this.classes = undefined;
        this.methods = undefined;
        this.assemblyFilter = undefined;
        this.classFilter = undefined;
        this.methodFilter = undefined;
        this.parameterFilter = undefined;
        this.generator = undefined;

        return this;
    }

    /** Reports method invocations. */
    simply(): Pick<Il2Cpp.Tracer, "trace"> {
        this.generator = (target: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
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
    fully(): Pick<Il2Cpp.Tracer, "trace"> {
        let counter = 0;

        this.generator = (target: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
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
    detailedly(): Pick<Il2Cpp.Tracer, "trace"> {
        let counter = 0;

        this.generator = (target: Il2Cpp.Method): Il2Cpp.Tracer.Callbacks => {
            const at = kleur.white(formatNativePointer(target.relativeVirtualAddress));
            const sign = `${target.class.type.name}.${kleur.bold(target.name)}`;
            const parametersInfo = Object.values(target.parameters);

            return {
                onEnter(...parameters: Il2Cpp.Parameter.Type[]): void {
                    const parametersText = parametersInfo
                        .map(({ type, name }, index) => {
                            return `${kleur.blue(type.name)} ${kleur.yellow(name)} = ${kleur.cyan(parameters[index] + "")}`;
                        })
                        .join(", ");

                    inform(`${at} ${"│ ".repeat(counter)}┌─${kleur.red(sign)}${kleur.yellow("(")}${parametersText}${kleur.yellow(")")}`);
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
    specially(generator: (target: Il2Cpp.Method) => Il2Cpp.Tracer.Callbacks): Pick<Il2Cpp.Tracer, "trace"> {
        this.generator = generator;
        return this;
    }

    trace(): void {
        for (const target of this.targets) {
            if (target.virtualAddress.isNull()) {
                continue;
            }

            const { onEnter, onLeave } = this.generator!(target);

            target.implementation = function (...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Method.ReturnType {
                onEnter?.apply(null, parameters);

                const returnValue = (this instanceof Il2Cpp.Object ? target.withHolder(this) : target).invoke(...parameters);

                onLeave?.call(null, returnValue);

                return returnValue;
            };
        }
    }

    static builder(): Pick<Il2Cpp.Tracer, "findInDomain" | "findInAssemblies" | "findInClasses" | "findInMethods"> {
        return new Il2Cpp.Tracer();
    }
}

type NonEmptyArray<T> = [T, ...T[]];

type FilterAssemblies = FilterClasses & Pick<Il2Cpp.Tracer, "withAssemblyFilter">;

type FilterClasses = FilterMethods & Pick<Il2Cpp.Tracer, "withClassFilter">;

type FilterMethods = FilterParameters & Pick<Il2Cpp.Tracer, "withMethodFilter">;

type FilterParameters = Pick<Il2Cpp.Tracer, "commitAnd"> & Pick<Il2Cpp.Tracer, "withParameterFilter">;

Il2Cpp.Tracer = Il2CppTracer;

declare global {
    namespace Il2Cpp {
        class Tracer extends Il2CppTracer {}

        namespace Tracer {
            type Callbacks = {
                onEnter?: (...parameters: Il2Cpp.Parameter.Type[]) => void;
                onLeave?: (returnValue: Il2Cpp.Method.ReturnType) => void;
            };
        }
    }
}
