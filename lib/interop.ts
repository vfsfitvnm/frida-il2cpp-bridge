/** @internal */
function fromFridaInvocationReturnValue(context: InvocationContext, retval: InvocationReturnValue, type: Il2Cpp.Type): Il2Cpp.Method.ReturnType {
    return interpretNativePointer(retval, type);
}

/** @internal */
function toFridaInvocationReturnValue(context: InvocationContext, value: Il2Cpp.Method.ReturnType, type: Il2Cpp.Type): NativePointer {
    return asNativePointer(value, type);
}

/** @internal */
function interpretNativePointer(value: NativePointer, type: Il2Cpp.Type): Il2Cpp.Method.ReturnType {
    switch (type.enumValue) {
        case Il2Cpp.Type.Enum.BOOLEAN:
            return !value.isNull();
        case Il2Cpp.Type.Enum.FLOAT:
            _nativePointerToFloatInput[0] = value.toUInt32();
            return _nativePointerToFloatOutput[0];
        case Il2Cpp.Type.Enum.DOUBLE:
            _nativePointerToDoubleInput[0] = BigInt(value.toString());
            return _nativePointerToDoubleOutput[0];
    }

    raise(`couldn't handle value ${value} using an unhandled or unknown type ${type.name} (${Il2Cpp.Type.Enum[type.enumValue]})`);
}

/** @internal */
function interpretArrayBuffer(buffer: ArrayBuffer, type: Il2Cpp.Type): Il2Cpp.Method.ReturnType {
    switch (type.enumValue) {
        case Il2Cpp.Type.Enum.FLOAT:
            return new Float32Array(buffer, 0, 1)[0];
        case Il2Cpp.Type.Enum.DOUBLE:
            return new Float64Array(buffer, 0, 1)[0];
    }

    raise(`interpreting an ArrayBuffer as ${type.name} (${Il2Cpp.Type.Enum[type.enumValue]}) is not yet implemented`);
}

/** @internal */
function asNativePointer<T extends Il2Cpp.Method.ReturnType>(value: T, type: Il2Cpp.Type): NativePointer {
    switch (type.enumValue) {
        case Il2Cpp.Type.Enum.BOOLEAN:
            if (typeof value == "boolean") {
                return ptr(+value);
            }
        case Il2Cpp.Type.Enum.FLOAT:
            if (typeof value == "number") {
                _nativePointerToFloatOutput[0] = value;
                return ptr(_nativePointerToFloatInput[0]);
            }
    }

    raise(`couldn't handle value ${value} using an unhandled or unknown type ${type.name} (${Il2Cpp.Type.Enum[type.enumValue]})`);
}

// function assertJsType<T extends Il2Cpp.Method.ReturnType>(value: T, type: Il2Cpp.Type) {
//     const expectedJsType = typeEnumToJsTypeMapping[Il2Cpp.Type.Enum[type.enumValue]];
// }

const typeEnumToJsTypeMapping = {
    VOID: "undefined",
    BOOLEAN: "boolean",
    CHAR: "number",
    BYTE: "number",
    UBYTE: "number",
    SHORT: "number",
    USHORT: "number",
    INT: "number",
    UINT: "number",
    LONG: ["number", Int64],
    ULONG: ["number", UInt64],
    NINT: NativePointer,
    NUINT: NativePointer,
    FLOAT: "number",
    DOUBLE: "number",
    POINTER: NativePointer,
    // VALUE_TYPE: Il2Cpp.ValueType,
    // OBJECT: Il2Cpp.Object,
    // STRING: Il2Cpp.String,
    // CLASS: Il2Cpp.Class,
    // ARRAY: Il2Cpp.Array,
    // NARRAY: Il2Cpp.Array,
    VAR: "undefined",
    MVAR: "undefined",
    GENERIC_INSTANCE: "undefined"
} as const;

type TypeEnumToJsTypeMapping = InferSchema<typeof typeEnumToJsTypeMapping>;

// prettier-ignore
type InferSchema<T> = 
  T extends "undefined" ? undefined :
  T extends "string" ? string :
  T extends "number" ? number :
  T extends "boolean" ? boolean :
  T extends new (...args: any[]) => infer R ? R :
  T extends readonly (infer U)[] ? InferSchema<U> :
  T extends object ? { [K in keyof T]: InferSchema<T[K]> } :
  never;

// JavaScript is single-threaded so no problems here
const _nativePointerToFloatInput = new Uint32Array(1);
const _nativePointerToFloatOutput = new Float32Array(_nativePointerToFloatInput.buffer);

// JavaScript is single-threaded so no problems here
const _nativePointerToDoubleInput = new BigUint64Array(1);
const _nativePointerToDoubleOutput = new Float32Array(_nativePointerToDoubleInput.buffer);
