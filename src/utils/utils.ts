import { closest } from "fastest-levenshtein";
import { raise } from "./console";

/** @internal */
export function* nativeIterator<T extends ObjectWrapper>(
    holder: NativePointerValue,
    nativeFunction: NativeFunction<NativePointer, [NativePointerValue, NativePointer]>,
    Class: new (handle: NativePointer) => T
): Generator<T> {
    const iterator = Memory.alloc(Process.pointerSize);
    let handle: NativePointer;

    while (!(handle = nativeFunction(holder, iterator)).isNull()) {
        yield new Class(handle);
    }
}

/** @internal */
export function cacheInstances<T extends ObjectWrapper, U extends new (handle: NativePointer) => T>(Class: U) {
    const instanceCache = new Map<number, T>();

    return new Proxy(Class, {
        construct(Target: U, argArray: [NativePointer]): T {
            const handle = argArray[0].toUInt32();

            if (!instanceCache.has(handle)) {
                instanceCache.set(handle, new Target(argArray[0]));
            }
            return instanceCache.get(handle)!;
        }
    });
}

/** @internal */
export function memoize(_: any, __: string, descriptor: PropertyDescriptor) {
    if (descriptor.value != null) {
        const map = new Map<string, any>();
        const original = descriptor.value;

        descriptor.value = function (...args: any[]): any {
            const key = args.toString();
            if (!map.has(key)) {
                const result = original.apply(this, args);
                if (result) {
                    map.set(key, result);
                }
            }
            return map.get(key);
        };
    }
}

/** @internal */
export function levenshtein(candidatesKey: string, nameGetter: (e: any) => string = e => e.name) {
    return function (_: any, propertyKey: string, descriptor: TypedPropertyDescriptor<(key: string, ...args: any[]) => any>) {
        const original = descriptor.value!;

        descriptor.value = function (this: any, key: string, ...args: any[]): any {
            const result = original.call(this, key, ...args);

            if (result != null) return result;

            const closestMatch = closest(key, this[candidatesKey].map(nameGetter));

            raise(`couldn't find ${propertyKey} ${key} in ${this.name}${closestMatch ? `, did you mean ${closestMatch}?` : ``}`);
        };
    };
}
