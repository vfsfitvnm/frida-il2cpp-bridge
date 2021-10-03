import { raise } from "../utils/console";
import { NativeStruct } from "../utils/native-struct";
import { Version } from "../utils/version";

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
export function checkNull(target: NativeStruct, propertyKey: "toString", descriptor: PropertyDescriptor): void {
    const original = descriptor.value;
    descriptor.value = function (this: NativeStruct): string {
        return this.isNull() ? "null" : original.apply(this);
    };
}
