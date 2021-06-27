import { raise } from "../utils/console";
import { injectToGlobal } from "../utils/decorators";

/** @internal */
export function shouldBeInstance<T extends Il2Cpp.Field | Il2Cpp.Method>(shouldBeInstance: boolean): MethodDecorator {
    return function (_: Object, __: PropertyKey, descriptor: PropertyDescriptor): void {
        const fn = descriptor.value ?? descriptor.get ?? descriptor.set;
        const key = descriptor.value ? "value" : descriptor.get ? "get" : "set";

        descriptor[key] = function (this: T, ...args: any[]): any {
            if (this.isStatic == shouldBeInstance) {
                raise(`${this.constructor.name} ("${this.name}") is ${shouldBeInstance ? "" : "not "}static.`);
            }
            return fn.apply(this, args);
        };
    };
}

/** @internal */
export function since(version: string): MethodDecorator {
    return function (_: Object, propertyKey: PropertyKey, descriptor: PropertyDescriptor): void {
        const fn = descriptor.value ?? descriptor.get ?? descriptor.set;
        const key = descriptor.value ? "value" : descriptor.get ? "get" : "set";

        descriptor[key] = function (...args: any[]): any {
            if (Il2Cpp.unityVersion.isBelow(version)) {
                raise(`${this.constructor.name}.${propertyKey.toString()} is available from version ${version} onwards.`);
            }
            return fn.apply(this, args);
        };
    };
}

/** @internal */
export function injectToIl2Cpp<K extends keyof typeof Il2Cpp, V extends typeof Il2Cpp[K]>(prop: K): (value: V) => V {
    return injectToGlobal("Il2Cpp", prop);
}
