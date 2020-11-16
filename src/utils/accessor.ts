import { closest } from "fastest-levenshtein";
import { raise } from "./console";

/** @internal */
export const filterAndMap = Symbol();

/** @internal */
export class Accessor<T> implements Iterable<T> {
    constructor(keyClashProtection = false) {
        return new Proxy(this, {
            set(target: Accessor<T>, key: PropertyKey, value: T) {
                if (typeof key == "string") {
                    // const basename = key.replace(/^[^a-zA-Z$_]|[^a-zA-Z0-9$_]/g, "_");
                    let name = key;
                    if (keyClashProtection) {
                        let count = 0;
                        while (Reflect.has(target, name)) name = key + "_" + ++count;
                    }
                    Reflect.set(target, name, value);
                } else {
                    Reflect.set(target, key, value);
                }
                return true;
            },
            get(target: Accessor<T>, key: PropertyKey) {
                if (typeof key != "string" || Reflect.has(target, key)) return Reflect.get(target, key);
                raise(`Couldn't find property "${key}", did you mean "${closest(key, Object.keys(target))}"?`);
            }
        });
    }

    *[Symbol.iterator]() {
        for (const value of Object.values(this)) yield value;
    }

    [filterAndMap]<U>(filter: (value: T) => boolean, map: (value: T) => U) {
        const accessor = new Accessor<U>();
        for (const [key, value] of Object.entries(this)) if (filter(value)) accessor[key] = map(value);
        return accessor;
    }

    [key: string]: T;
}
