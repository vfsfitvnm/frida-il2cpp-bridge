/** @internal */
function lazy(_: any, propertyKey: PropertyKey, descriptor: PropertyDescriptor) {
    const getter = descriptor.get;

    if (!getter) {
        throw new Error("@lazy can only be applied to getter accessors");
    }

    descriptor.get = function (this: unknown & { _propertyCache?: Record<PropertyKey, any> }) {
        if (!this._propertyCache) {
            Object.defineProperty(this, "_propertyCache", {
                value: {},
                configurable: false,
                enumerable: false,
                writable: true
            });
        }

        if (!(propertyKey in this._propertyCache!)) {
            this._propertyCache![propertyKey] = getter.call(this);
        }

        return this._propertyCache![propertyKey];
    };

    return descriptor;
}
