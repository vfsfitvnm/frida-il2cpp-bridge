import { AllowedType } from "./types";

/**
 * Represents something which has an accessible value.
 */
export interface Valuable {
    /**
     * The actual "pretty" value.
     */
    value: AllowedType;
    /**
     * The actual location.
     */
    valueHandle: NativePointer;
}

/**
 * Represents an invokable method.
 */
export interface Invokable {
    /**
     * See {@link Il2CppMethod.invoke}.
     */
    invoke<T extends AllowedType>(...parameters: AllowedType[]): T;
}
