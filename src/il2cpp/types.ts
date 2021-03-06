import { Il2CppValueType } from "./structs/value-type";
import { Il2CppObject } from "./structs/object";
import { Il2CppString } from "./structs/string";
import { Il2CppArray } from "./structs/array";
import { Accessor } from "../utils/accessor";
import { Valuable } from "./interfaces";

/**
 * Types this module is familiar with.
 */
export type AllowedType =
    | undefined
    | boolean
    | number
    | Int64
    | UInt64
    | NativePointer
    | Il2CppValueType
    | Il2CppObject
    | Il2CppString
    | Il2CppArray<AllowedType>;

/**
 * Callback of a method implementation.
 */
export type ImplementationCallback =
    /**
     * @param this Frida's `InvocationContext`.
     * @param instance Instance whose method is being intercepted, `null` if the
     * method is static.
     * @param parameters Invocation parameters.
     * @return The value that should be returned - mandatory.
     */
    (this: InvocationContext, instance: Il2CppObject | null, parameters: Accessor<Valuable>) => AllowedType;

/**
 * Callback of a method `onEnter` interception.
 */
export type OnEnterCallback =
    /**
     * @param this Frida's `InvocationContext`.
     * @param instance Instance whose method is being intercepted, `null` if the
     * method is static.
     * @param parameters Invocation parameters.
     */
    (this: InvocationContext, instance: Il2CppObject | null, parameters: Accessor<Valuable>) => void;

/**
 * Callback of a method `onLeave` interception.
 */
export type OnLeaveCallback =
    /**
     * @param this Frida's `InvocationContext`.
     * @param returnValue The value that should be returned.
     */
    (this: InvocationContext, returnValue: Valuable) => void;
