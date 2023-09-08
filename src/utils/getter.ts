/** @internal */
function getter<T, K extends keyof T>(
    target: T,
    key: K,
    get: () => T[K],
    decorator?: (target: T, key: K, descriptor: PropertyDescriptor) => PropertyDescriptor
) {
    globalThis.Object.defineProperty(target, key, decorator?.(target, key, { get, configurable: true }) ?? { get, configurable: true });
}
