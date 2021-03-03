type Base = {
    bool: boolean;
    int: number;
    uint: number;
    long: number;
    ulong: number;
    char: number;
    uchar: number;
    float: number;
    double: number;
    int8: number;
    uint8: number;
    int16: number;
    uint16: number;
    int32: number;
    uint32: number;
    int64: Int64;
    uint64: UInt64;
    size_t: UInt64;
    ssize_t: Int64;
    pointer: NativePointer;
};

type NFI = {
    utf8string: string;
    utf16string: string;
    ansistring: string;
} & Base;

type NFO = {
    void: undefined;
} & Base &
    NCI;

type NCI = {
    cstring: string | null;
    utf8string: string | null;
    utf16string: string | null;
    ansistring: string | null;
} & Base;

type NCO = {
    void: void;
} & Base &
    NFI;

type Extract<T, V extends (keyof T)[]> = { [P in keyof V]: V[P] extends keyof T ? T[V[P]] : never };

function getTypeAliasForFrida(type: keyof NFI | keyof NFO | keyof NCI | keyof NCO) {
    switch (type) {
        case "ansistring":
        case "utf8string":
        case "utf16string":
        case "cstring":
            return "pointer";
        default:
            return type;
    }
}

function refinedToRaw<T extends keyof NFI | keyof NCO>(value: any, type: T): any {
    switch (typeof value) {
        case "boolean":
            return +value;
        case "string": {
            switch (type) {
                case "utf8string":
                    return Memory.allocUtf8String(value);
                case "utf16string":
                    return Memory.allocUtf16String(value);
                case "ansistring":
                    return Memory.allocAnsiString(value);
            }
            break;
        }
    }
    return value;
}

function rawToRefined<T extends keyof NFO | keyof NCI>(value: NativeReturnValue | any, type: T): any {
    switch (typeof value) {
        case "number":
            if (type == "bool") return !!value;
            break;
        case "object": {
            if (value instanceof NativePointer) {
                switch (type) {
                    case "utf8string":
                        return value.readUtf8String();
                    case "utf16string":
                        return value.readUtf16String();
                    case "ansistring":
                        return value.readAnsiString();
                    case "cstring":
                        return value.readCString();
                }
            }
            break;
        }
    }
    return value;
}

/**
 * @internal
 * Creates a `NativeFunction`.
 * @param address The function
 * @param retType The callback return type.
 * @param argTypes The callback arguments types.
 * @param options Follows Frida API.
 */
export function createNF<R extends keyof NFO, P extends (keyof NFI)[]>(
    address: NativePointer,
    retType: R,
    argTypes: [...P],
    options?: NativeFunctionOptions
) {
    const fn = new NativeFunction(address, getTypeAliasForFrida(retType), argTypes.map(getTypeAliasForFrida), options);
    return (...args: Extract<NFI, P>): NFO[R] => rawToRefined(fn(...args.map((v, i) => refinedToRaw(v, argTypes[i]))), retType);
}

/**
 * @internal
 * Creates a `NativeCallback`.
 * @param callback The function to execute.
 * @param retType The callback return type.
 * @param argTypes The callback arguments types.
 * @param abi Follows Frida API.
 */
export function createNC<R extends keyof NCO, P extends (keyof NCI)[]>(
    callback: (...args: Extract<NCI, P>) => NCO[R],
    retType: R,
    argTypes: [...P],
    abi?: NativeABI
) {
    const cb = (...params: any[]) => refinedToRaw(callback(...(params.map((v, i) => rawToRefined(v, argTypes[i])) as any)), retType);
    return new NativeCallback(cb, getTypeAliasForFrida(retType), argTypes.map(getTypeAliasForFrida), abi);
}
