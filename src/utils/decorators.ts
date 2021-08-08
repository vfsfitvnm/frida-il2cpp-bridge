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

type FromPath<T, Path extends string> = Path extends `${infer Key}.${infer Rest}`
    ? Key extends keyof T
        ? FromPath<T[Key], Rest>
        : never
    : Path extends keyof T
    ? T[Path]
    : never;

type ValueFromPath<Path extends string> = FromPath<typeof globalThis, Path>;

type ClassFromPath<Path extends string> = ValueFromPath<Path> & { new (...args: any): any };

/** @internal */
export function injectValue<Path extends string, Value extends ValueFromPath<Path>>(
    path: Path,
    override: boolean = false
): (value: Value) => void {
    const keys = path.split(".");
    let target: any = globalThis;

    for (let i = 0; i < keys.length - 1; i++) {
        target = target[keys[i]] = target[keys[i]] || {};
    }

    return (value: Value): void => {
        target[keys[keys.length - 1]] = override ? value : target[keys[keys.length - 1]] || value;
    };
}

/** @internal */
export function injectClass<Path extends string, Value extends ClassFromPath<Path>>(
    path: Path,
    override: boolean = false
): (value: Value) => void {
    return injectValue<Path, Value>(path, override);
}
