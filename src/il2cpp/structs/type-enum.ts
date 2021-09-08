/** Represents a `Il2CppTypeEnum`. */
type Il2CppTypeEnum =
    | "end"
    | "void"
    | "boolean"
    | "char"
    | "i1"
    | "u1"
    | "i2"
    | "u2"
    | "i4"
    | "u4"
    | "i8"
    | "u8"
    | "r4"
    | "r8"
    | "string"
    | "ptr"
    | "byref"
    | "valuetype"
    | "class"
    | "var"
    | "array"
    | "genericinst"
    | "typedbyref"
    | "i"
    | "u"
    | "fnptr"
    | "object"
    | "szarray"
    | "mvar"
    | "cmod_reqd"
    | "cmod_opt"
    | "internal"
    | "modifier"
    | "sentinel"
    | "pinned"
    | "enum";

declare global {
    namespace Il2Cpp {
        namespace Type {
            type Enum = Il2CppTypeEnum;
        }
    }
}

export {};
