import { raise } from "./console";

/** @internal BaseType */
type BT =
    | "bool"
    | "int"
    | "uint"
    | "long"
    | "ulong"
    | "char"
    | "uchar"
    | "float"
    | "double"
    | "int8"
    | "uint8"
    | "int16"
    | "uint16"
    | "int32"
    | "uint32"
    | "int64"
    | "uint64"
    | "utf8string"
    | "utf16string"
    | "ansistring"
    | "pointer";

/** @internal ConcreteBaseType */
type CBT = boolean | number | string | Int64 | UInt64 | NativePointer;

/** @internal */
type ToCBT<T extends BT> = T extends "bool"
    ? boolean
    : T extends "int"
    ? number
    : T extends "uint"
    ? number
    : T extends "long"
    ? number
    : T extends "ulong"
    ? number
    : T extends "char"
    ? number
    : T extends "uchar"
    ? number
    : T extends "float"
    ? number
    : T extends "double"
    ? number
    : T extends "int8"
    ? number
    : T extends "uint8"
    ? number
    : T extends "int16"
    ? number
    : T extends "uint16"
    ? number
    : T extends "int32"
    ? number
    : T extends "uint32"
    ? number
    : T extends "int64"
    ? Int64
    : T extends "uint64"
    ? UInt64
    : T extends "pointer"
    ? NativePointer
    : never;

/** @internal InputBaseType */
type IBT = BT;

/** @internal InputConcreteType */
type ICT = CBT;

/** @internal */
type ToICT<T extends IBT> = T extends "utf8string"
    ? string
    : T extends "utf16string"
    ? string
    : T extends "ansistring"
    ? string
    : T extends BT
    ? ToCBT<T>
    : never;

/** @internal */
type ToICTs<T extends IBT[]> = {
    [P in keyof T]: T[P] extends IBT ? ToICT<T[P]> : never;
};

/** @internal OutputBaseType */
type OBT = BT | "void" | "cstring";

/** @internal OutputConcreteType */
type OCT = CBT | void | null;

/** @internal */
type ToOCT<T extends OBT> = T extends "void"
    ? void
    : T extends "cstring"
    ? string | null
    : T extends "utf8string"
    ? string | null
    : T extends "utf16string"
    ? string | null
    : T extends "ansistring"
    ? string | null
    : T extends BT
    ? ToCBT<T>
    : never;

/** @internal */
type F<RT extends OBT, PT extends IBT[]> = (...args: ToICTs<PT>) => ToOCT<RT>;

/** @internal */
const options: NativeFunctionOptions = { scheduling: "exclusive", exceptions: "propagate" };

/** @internal */
export const sources: (Module | CModule)[] = [];

/** @internal */
export function create<RT extends OBT, PT extends IBT[]>(retType: RT, exportName: string, ...argTypes: PT): F<RT, PT> {
    const exportPointer = resolve(exportName);

    const returnTypeAlias = getTypeAliasForFrida(retType);
    const argTypesAliases = argTypes.map(getTypeAliasForFrida);

    const nativeFunction = new NativeFunction(exportPointer, returnTypeAlias, argTypesAliases, options);

    return Object.assign(
        (...args: ICT[]): OCT => {
            const transformedArgs = args.map((v, i) => getValueForFrida(v, argTypes[i]));
            const returnValue = nativeFunction(...transformedArgs);

            switch (retType) {
                case "bool":
                    return !!+returnValue;
                case "ansistring":
                    return (returnValue as NativePointer).readAnsiString();
                case "utf8string":
                    return (returnValue as NativePointer).readUtf8String();
                case "utf16string":
                    return (returnValue as NativePointer).readUtf16String();
                case "cstring":
                    return (returnValue as NativePointer).readCString();
                default:
                    return returnValue as ToOCT<RT>;
            }
        }
    );
}

/** @internal */
export function resolve(exportName: string) {
    for (const source of sources) {
        const result = source instanceof Module ? source.findExportByName(exportName) : source[exportName];
        if (result) return result as NativePointer;
    }
    raise(`Couldn't resolve export "${exportName}".`);
}

/** @internal */
function getTypeAliasForFrida(type: IBT | OBT) {
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

/** @internal */
function getValueForFrida(value: ICT, type: IBT) {
    switch (type) {
        case "bool":
            return +(value as boolean);
        case "utf8string":
            return Memory.allocUtf8String(value as string);
        case "utf16string":
            return Memory.allocUtf16String(value as string);
        case "ansistring":
            return Memory.allocAnsiString(value as string);
        case "pointer":
            return value as NativePointer;
        default:
            return value as number;
    }
}
