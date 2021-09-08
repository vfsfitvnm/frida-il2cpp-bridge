import { raise } from "../utils/console";
import { NativeStruct } from "../utils/native-struct";

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
export function since(version: string): MethodDecorator;
/** @internal */
export function since(getterVersion: string, setterVersion: string): MethodDecorator;
/** @internal */
export function since(version0: string, version1?: string): MethodDecorator {
    return function (target: any, propertyKey: PropertyKey, descriptor: PropertyDescriptor): void {
        const fn = descriptor.value ?? descriptor.get ?? descriptor.set;
        const key = descriptor.value ? "value" : descriptor.get ? "get" : "set";

        descriptor[key] = function (...args: any[]): any {
            if (Il2Cpp.unityVersion.isBelow(version0)) {
                const verb = descriptor.value ? "Calling" : descriptor.get ? "Getting" : "Setting";
                const prop = `${("prototype" in target ? target.prototype : target).constructor.name}.${propertyKey.toString()}`;
                raise(`${verb} ${prop} is available from version ${version0} onwards.`);
            }
            return fn.apply(this, args);
        };

        if (version1 != undefined) {
            descriptor.set = function (...args: any[]): any {
                if (Il2Cpp.unityVersion.isBelow(version1)) {
                    const prop = `${("prototype" in target ? target.prototype : target).constructor.name}.${propertyKey.toString()}`;
                    raise(`Setting ${prop} is available from version ${version0} onwards.`);
                }
                return fn.apply(this, args);
            };
        }
    };
}

/** @internal */
export function checkNull(target: NativeStruct, propertyKey: "toString", descriptor: PropertyDescriptor): void {
    const original = descriptor.value;
    descriptor.value = function (this: NativeStruct): string {
        return this.isNull() ? "null" : original.apply(this);
    };
}
