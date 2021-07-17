import { closest } from "fastest-levenshtein";
import { raise } from "./console";

function setterWithKeyClashProtection<T extends PropertyKey, V>(target: Record<T, V>, key: PropertyKey, value: V): boolean {
    if (typeof key == "string") {
        while (key in target) {
            key += "_";
        }
    }

    Reflect.set(target, key, value);
    return true;
}

function getterWithLevenshtein<T extends PropertyKey, V>(target: Record<T, V>, key: PropertyKey): T {
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

/** @internal */
export function preventKeyClash<T extends PropertyKey, V>(object: Record<T, V>): Record<T, V> {
    return new Proxy(object, { set: setterWithKeyClashProtection });
}

/** @internal */
export function addLevenshtein<T extends PropertyKey, V>(object: Record<T, V>): Record<T, V> {
    return new Proxy(object, { get: getterWithLevenshtein });
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
