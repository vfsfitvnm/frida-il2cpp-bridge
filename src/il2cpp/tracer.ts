import { injectToIl2Cpp } from "./decorators";
import { inform, warn } from "../utils/console";

@injectToIl2Cpp("Tracer")
class Tracing {
    counter: number = 0;

    readonly invocationListeners: InvocationListener[] = [];

    constructor(readonly logging: Il2Cpp.Tracer.Logging, ...targets: (Il2Cpp.Class | Il2Cpp.Method)[]) {
        this.add(...targets);
    }

    static Custom(callbackGenerator: Il2Cpp.Tracer.Logging, ...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer {
        return new Il2Cpp.Tracer(callbackGenerator, ...targets);
    }

    static Full(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer {
        return new Il2Cpp.Tracer(function (method: Il2Cpp.Method) {
            const tracer: Il2Cpp.Tracer = this;
            const at = `\x1b[37m${method.relativePointerAsString}\x1b[0m`;
            const sign = `${method.class.type.name}.\x1b[1m${method.name}\x1b[0m`;

            return {
                onEnter() {
                    inform(`${at} ${"│ ".repeat(tracer.counter)}┌─\x1b[31m${sign}\x1b[0m`);
                    tracer.counter += 1;
                },
                onLeave() {
                    tracer.counter -= 1;
                    inform(`${at} ${"│ ".repeat(tracer.counter)}└─\x1b[32m${sign}\x1b[0m`);

                    if (tracer.counter == 0) {
                        console.log();
                    }
                }
            };
        }, ...targets);
    }

    static Simple(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer {
        return new Il2Cpp.Tracer(
            method => ({
                onEnter() {
                    inform(`\x1b[37m${method.relativePointerAsString}\x1b[0m ${method.class.type.name}.\x1b[1m${method.name}\x1b[0m`);
                }
            }),
            ...targets
        );
    }

    add(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): void {
        const methods = targets
            .flatMap(target => (target instanceof Il2Cpp.Class ? Object.values(target.methods) : target))
            .filter(method => !method.pointer.isNull());

        for (const method of methods) {
            try {
                this.invocationListeners.push(Interceptor.attach(method.pointer, this.logging.call(this, method)));
            } catch (e) {
                warn(`Can't trace method ${method.name} from ${method.class.type.name}: ${e.message}.`);
            }
        }
    }

    clear(): void {
        let invocationListener: InvocationListener | undefined;

        while ((invocationListener = this.invocationListeners.pop())) {
            invocationListener.detach();
        }
    }
}

@injectToIl2Cpp("Tracer2")
class Tracer {
    counter: number = 0;

    readonly methods: Il2Cpp.Method[];

    constructor(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]) {
        this.methods = targets
            .flatMap(target => (target instanceof Il2Cpp.Class ? Object.values(target.methods) : target))
            .filter(method => !method.pointer.isNull());

        // for (const method of methods) {
        //     try {
        //         this.invocationListeners.push(Interceptor.replace(method.pointer, this.logging.call(this, method)));
        //     } catch (e) {
        //         warn(`Can't trace method ${method.name} from ${method.class.type.name}: ${e.message}.`);
        //     }
        // }
    }

    static FullWithValues(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer2 {
        const tracer = new Il2Cpp.Tracer2(...targets);

        for (const method of tracer.methods) {
            const at = `\x1b[37m${method.relativePointerAsString}\x1b[0m`;
            const sign = `${method.class.type.name}.\x1b[1m${method.name}\x1b[0m`;

            method.implementation = function (...parameters: Il2Cpp.AllowedType[]): Il2Cpp.AllowedType {
                const parametersInfo = parameters.join(", ");

                inform(`${at} ${"│ ".repeat(tracer.counter)}┌─\x1b[31m${sign}\x1b[0m\x1b[33m(\x1b[0m${parametersInfo}\x1b[33m)\x1b[0m`);
                tracer.counter += 1;

                let result: Il2Cpp.AllowedType;
                if (this instanceof Il2Cpp.Object) {
                    result = method.asHeld(this.handle).invoke(...parameters);
                } else {
                    result = method.invoke(...parameters);
                }

                tracer.counter -= 1;
                inform(
                    `${at} ${"│ ".repeat(tracer.counter)}└─\x1b[32m${sign}\x1b[0m \x1b[35m${
                        method.returnType.name
                    }\x1b[0m = \x1b[36m${result}\x1b[0m`
                );
                if (tracer.counter == 0) {
                    console.log();
                }

                return result;
            };
        }

        return tracer;
    }

    clear(): void {
        let method: Il2Cpp.Method | undefined;

        while ((method = this.methods.pop())) {
            method.restoreImplementation();
        }
    }
}
