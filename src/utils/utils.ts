import { closest } from "fastest-levenshtein";

import { raise } from "./console";

/** @internal */
export function preventKeyClash<T extends PropertyKey, V>(object: Record<T, V>): Record<T, V> {
    return new Proxy(object, {
        set<T extends PropertyKey, V>(target: Record<T, V>, key: PropertyKey, value: V): boolean {
            if (typeof key == "string") {
                while (key in target) {
                    key += "_";
                }
            }

            Reflect.set(target, key, value);
            return true;
        }
    });
}

/** @internal */
export function addLevenshtein<T extends PropertyKey, V>(object: Record<T, V>): Record<T, V> {
    return new Proxy(object, {
        get<T extends PropertyKey, V>(target: Record<T, V>, key: PropertyKey): T {
            if (typeof key != "string" || key in target) {
                return Reflect.get(target, key);
            }

            const closestMatch = closest(key, Object.keys(target));
            if (closestMatch) {
                raise(`Couldn't find property "${key}", did you mean "${closestMatch}"?`);
            } else {
                raise(`Couldn't find property "${key}".`);
            }
        }
    });
}

/** @internal */
export function getUntilFound<T extends PropertyKey, V>(record: Readonly<Record<T, V>>, ...keys: T[]): V | undefined {
    for (const key of keys) {
        if (key in record) {
            return record[key];
        }
    }
}

/** @internal */
export function map<V, U>(source: Record<string, V>, map: (value: V) => U): Record<string, U> {
    const record: Record<string, U> = {};

    for (const [key, value] of Object.entries(source)) {
        record[key] = map(value);
    }

    return record;
}

/** @internal */
export function filterMap<V, U>(source: Record<string, V>, filter: (value: V) => boolean, map: (value: V) => U): Record<string, U> {
    const record: Record<string, U> = {};

    for (const [key, value] of Object.entries(source)) {
        if (filter(value)) {
            record[key] = map(value);
        }
    }

    return record;
}

/** @internal */
export function filterMapArray<V, U>(source: Record<string, V>, filter: (value: V) => boolean, map: (value: V) => U): U[] {
    const dest: U[] = [];

    for (const value of Object.values(source)) {
        if (filter(value)) {
            dest.push(map(value));
        }
    }

    return dest;
}

/** @internal */
export function mapToArray<V, U>(source: Record<string, V>, map: (value: V) => U): U[] {
    const dest: U[] = [];

    for (const value of Object.values(source)) {
        dest.push(map(value));
    }

    return dest;
}

/** @internal */
export function overridePropertyValue<T extends object, K extends keyof T>(target: T, property: K, value: T[K]): T {
    Reflect.defineProperty(target, property, { value: value });
    return target;
}

/** @internal */
export function redefineProperty<T extends object, K extends keyof T>(
    target: T,
    property: K,
    descriptor: RequireAtLeastOne<{ get?: () => T[K]; set?: (value: T[K]) => void }>
): T {
    Reflect.defineProperty(target, property, descriptor);
    return target;
}

/** @internal */
export function formatNativePointer(nativePointer: NativePointer): string {
    return `0x${nativePointer.toString(16).padStart(8, "0")}`;
}
