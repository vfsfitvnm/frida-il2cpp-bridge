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
function assertVersion(block: (other: string) => boolean, version: string): MethodDecorator {
    function getName(): string {
        switch (block) {
            case Version.prototype.isAbove:
                return "is not above";
            case Version.prototype.isBelow:
                return "is not below";
            case Version.prototype.isEqual:
                return "is not equal to";
            case Version.prototype.isEqualOrAbove:
                return "is not equal to or above";
            case Version.prototype.isEqualOrBelow:
                return "is not equal to or below";
            default:
                return "unknown";
        }
    }

    return function (target: any, propertyKey: PropertyKey, descriptor: PropertyDescriptor): void {
        const fn = descriptor.value ?? descriptor.get ?? descriptor.set;
        const key = descriptor.value ? "value" : descriptor.get ? "get" : "set";

        descriptor[key] = function (...args: any[]): any {
            if (!block.call(Unity.version, version)) {
                const prop = `${("prototype" in target ? target.prototype : target).constructor.name}.${propertyKey.toString()}`;
                raise(`Cannot invoke ${prop}: the current unity version "${Unity.version}" ${getName()} version "${version}".`);
            }
            Reflect.defineProperty(target, propertyKey, {
                ...descriptor,
                [key]: fn
            });
            return fn.apply(this, args);
        };
    };
}

/** @internal */
export function isEqualOrAbove(version: string): MethodDecorator {
    return assertVersion(Version.prototype.isEqualOrAbove, version);
}

/** @internal */
export function isBelow(version: string): MethodDecorator {
    return assertVersion(Version.prototype.isBelow, version);
}

/** @internal */
export function checkNull(target: NativeStruct, propertyKey: "toString", descriptor: PropertyDescriptor): void {
    const original = descriptor.value;
    descriptor.value = function (this: NativeStruct): string {
        return this.isNull() ? "null" : original.apply(this);
    };
}
