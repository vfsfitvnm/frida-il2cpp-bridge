/** @internal */
export function injectToGlobal<T extends keyof typeof global, K extends keyof typeof global[T], V extends typeof global[T][K]>(
    target: T,
    prop: K
): (value: V) => V {
    (global as any)[target] = (global as any)[target] || {};

    return (value: V): V => {
        global[target][prop] = global[target][prop] || value;
        return value;
    };
}
