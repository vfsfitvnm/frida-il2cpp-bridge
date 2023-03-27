/** Tracing utilities. */
export abstract class AbstractTracer {
    /** @internal */
    readonly targets: Il2Cpp.Method[] = [];
    /** @internal */
    readonly startTargets: string[] = [];

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

    domain(): FilterAssemblies {
        return this;
    }

    assemblies(...assemblies: Il2Cpp.Assembly[]): FilterClasses {
        this.#assemblies = assemblies;
        return this;
    }

    classes(...classes: Il2Cpp.Class[]): FilterMethods {
        this.#classes = classes;
        return this;
    }

    methods(...methods: Il2Cpp.Method[]): FilterParameters {
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

    filterParameters(filter: (parameter: Il2Cpp.Parameter) => boolean): Pick<AbstractTracer, "and"> & Pick<AbstractTracer, "start"> {
        this.#parameterFilter = filter;
        return this;
    }

    and(): Pick<AbstractTracer, "domain" | "assemblies" | "classes" | "methods" | "attach"> {
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

        return this;
    }

    start(): Pick<AbstractTracer, "domain" | "assemblies" | "classes" | "methods" | "attach"> {
        const filterMethod = (method: Il2Cpp.Method): void => {
            if (this.#parameterFilter == undefined) {
                this.startTargets.push(method.handle.toString());
                return;
            }

            for (const parameter of method.parameters) {
                if (this.#parameterFilter(parameter)) {
                    this.startTargets.push(method.handle.toString());
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

        return this;
    }

    abstract attach(): void;
}

type FilterAssemblies = FilterClasses & Pick<AbstractTracer, "filterAssemblies">;

type FilterClasses = FilterMethods & Pick<AbstractTracer, "filterClasses">;

type FilterMethods = FilterParameters & Pick<AbstractTracer, "filterMethods">;

type FilterParameters = Pick<AbstractTracer, "and"> & Pick<AbstractTracer, "start"> & Pick<AbstractTracer, "filterParameters">;
