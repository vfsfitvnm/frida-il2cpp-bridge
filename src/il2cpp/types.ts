import { Accessor } from "utils";

import { Valuable } from "./interfaces";

import { _Il2CppArray } from "./structs/array";
import { _Il2CppObject } from "./structs/object";
import { _Il2CppString } from "./structs/string";
import { _Il2CppValueType } from "./structs/value-type";

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
    | _Il2CppValueType
    | _Il2CppObject
    | _Il2CppString
    | _Il2CppArray<AllowedType>;

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
    (this: InvocationContext, instance: _Il2CppObject | null, parameters: Accessor<Valuable>) => AllowedType;

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
    (this: InvocationContext, instance: _Il2CppObject | null, parameters: Accessor<Valuable>) => void;

/**
 * Callback of a method `onLeave` interception.
 */
export type OnLeaveCallback =
    /**
     * @param this Frida's `InvocationContext`.
     * @param returnValue The value that should be returned.
     */
    (this: InvocationContext, returnValue: Valuable) => void;
