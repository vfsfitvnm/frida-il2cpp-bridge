/** @internal */
function addFlippedEntries<T extends Record<any, any>>(obj: T): T & { [K in keyof T as T[K]]: K } {
    return Object.keys(obj).reduce((obj, key) => (((obj[obj[key]] as any) = key), obj), obj);
}
