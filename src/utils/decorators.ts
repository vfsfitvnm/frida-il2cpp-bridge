/** @internal */
export function lazy(target: any, key: PropertyKey, descriptor: PropertyDescriptor): any {
    return {
        get() {
            Reflect.defineProperty(this, key, { value: descriptor.get?.call(this) });
            return Reflect.get(this, key);
        }
    };
}
