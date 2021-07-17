/** @internal */
export function injectToGlobal<T extends keyof typeof globalThis, K extends keyof typeof globalThis[T], V extends typeof globalThis[T][K]>(
    target: T,
    prop: K
): (value: V) => V {
    (globalThis as any)[target] = (globalThis as any)[target] || {};

    return (value: V): V => {
        globalThis[target][prop] = globalThis[target][prop] || value;
        return value;
    };
}
