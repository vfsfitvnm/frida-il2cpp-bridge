import { closest } from "fastest-levenshtein";
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
export function checkNull(target: NativeStruct, propertyKey: "toString", descriptor: PropertyDescriptor): void {
    const original = descriptor.value;
    descriptor.value = function (this: NativeStruct): string {
        return this.isNull() ? "null" : original.apply(this);
    };
}

/** @internal */
export function levenshtein(candidatesKey: string, nameGetter: (e: any) => string = e => e.name) {
    return function (_: any, propertyKey: string, descriptor: TypedPropertyDescriptor<(key: string) => any>) {
        const original = descriptor.value!;

        descriptor.value = function (this: any, key: string): any {
            const result = original.call(this, key);

            if (result != null) return result;

            const closestMatch = closest(key, this[candidatesKey].map(nameGetter));

            raise(`Couldn't find ${propertyKey} '${key}' in '${this.name}'${closestMatch ? `, did you mean '${closestMatch}'?` : "."}`);
        };
    };
}
