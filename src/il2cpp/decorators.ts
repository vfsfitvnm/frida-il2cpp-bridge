import { raise } from "../utils/console";

import { AllowedType } from "./types";
import { NativeStruct } from "./native-struct";
import { unityVersion } from "./variables";

import { _Il2CppArray } from "./structs/array";
import { _Il2CppField } from "./structs/field";
import { _Il2CppMethod } from "./structs/method";

/** @internal */
export function shouldBeInstance<T extends _Il2CppField | _Il2CppMethod>(shouldBeInstance: boolean): MethodDecorator {
    return function (_: Object, __: PropertyKey, descriptor: PropertyDescriptor): void {
        const fn = descriptor.value ?? descriptor.get ?? descriptor.set;
        const key = descriptor.value ? "value" : descriptor.get ? "get" : "set";

        descriptor[key] = function (this: T, ...args: any[]): any {
            if (this.isInstance != shouldBeInstance) {
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
            if (unityVersion.isBelow(version)) {
                raise(`${this.constructor.name}.${propertyKey.toString()} is available from version ${version} onwards.`);
            }
            return fn.apply(this, args);
        };
    };
}

/** @internal */
export function nonNullMethodPointer<T extends _Il2CppMethod>(_: T, propertyKey: PropertyKey, descriptor: PropertyDescriptor): void {
    const fn = descriptor.value ?? descriptor.get ?? descriptor.set;
    const key = descriptor.value ? "value" : descriptor.get ? "get" : "set";

    descriptor[key] = function (this: T, ...args: any[]): any {
        if (this.actualPointer.isNull()) {
            raise(`Can't ${propertyKey.toString()} method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
        }
        return fn.apply(this, args);
    };
}

/** @internal */
export function checkOutOfBounds<T extends _Il2CppArray<AllowedType>>(_: T, __: PropertyKey, descriptor: PropertyDescriptor): void {
    const fn = descriptor.value;
    descriptor.value = function (this: T, ...args: any[]) {
        const index = args[0];
        if (index < 0 || index >= this.length) {
            raise(`${this.constructor.name} element index '${index}' out of bounds (length: ${this.length}).`);
        }
        return fn.apply(this, args);
    };
}

/** @internal */
export function nonNullHandle<T extends { new (...args: any[]): NativeStruct }>(Class: T): T {
    return new Proxy(Class, {
        construct(Class, args: any[]): NativeStruct {
            const constructed = new Class(...args);
            if (constructed.handle.isNull()) {
                raise(`Handle for "${Class.name}" cannot be NULL.`);
            }
            return constructed;
        }
    });
}

// export function nonNullHandle<T extends { new (...args: any[]): { handle: NativePointer } }>(Class: T): T {
//     const NewClass = class extends Class {
//         constructor(...args: any[]) {
//             super(...args);
//             if (this.handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
//         }
//     };
//     Reflect.defineProperty(NewClass, "name", { get: () => Class.name });
//     return NewClass;
// }
