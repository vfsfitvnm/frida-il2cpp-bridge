import { cache } from "decorator-cache-getter";

import { Accessor, filterAndMap } from "../../utils/accessor";
import { inform, raise, warn } from "../../utils/console";

import { Api } from "../api";
import { nonNullHandle, shouldBeInstance } from "../decorators";
import { Invokable, Valuable } from "../interfaces";
import { NativeStruct } from "../native-struct";
import { library, unityVersion } from "../variables";
import { allocRawValue, readRawValue } from "../utils";
import { AllowedType, ImplementationCallback, OnEnterCallback, OnLeaveCallback } from "../types";

import { _Il2CppClass } from "./class";
import { _Il2CppObject } from "./object";
import { _Il2CppType } from "./type";
import { _Il2CppParameter } from "./parameter";

/**
 * Represents a `MethodInfo`.
 */
@nonNullHandle
export class _Il2CppMethod extends NativeStruct {
    /**
     * ```typescript
     * const MathClass = mscorlib.classes["System.Math"];
     * Interceptor.attach(MathClass.actualPointer, {
     *     // ...
     * });
     * ```
     * @return Its actual pointer in memory.
     */
    @cache
    get actualPointer(): NativePointer {
        return Api._methodGetPointer(this.handle);
    }

    /**
     * @return The class it belongs to.
     */
    @cache
    get class(): _Il2CppClass {
        return new _Il2CppClass(Api._methodGetClass(this.handle));
    }

    /**
     * @return `true` if it's generic, `false` otherwise.
     */
    @cache
    get isGeneric(): boolean {
        return Api._methodIsGeneric(this.handle);
    }

    /**
     * @return `true` if it's inflated (a generic with a concrete type parameter),
     * false otherwise.
     */
    @cache
    get isInflated(): boolean {
        return Api._methodIsInflated(this.handle);
    }

    /**
     *  @return `true` if it's an instance method, `false` otherwise.
     */
    @cache
    get isInstance(): boolean {
        return Api._methodIsInstance(this.handle);
    }

    /**
     * @return Its name.
     */
    @cache
    get name(): string {
        return Api._methodGetName(this.handle)!;
    }

    /**
     * @return The count of its parameters.
     */
    @cache
    get parameterCount(): number {
        return Api._methodGetParamCount(this.handle);
    }

    /**
     * We can iterate over the parameters using a `for..of` loop,
     * or access a specific parameter using its name.
     * @return Its parameters.
     */
    @cache
    get parameters(): Accessor<_Il2CppParameter> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<_Il2CppParameter>();
        let handle: NativePointer;
        let parameter: _Il2CppParameter;
        while (!(handle = Api._methodGetParameters(this.handle, iterator)).isNull()) {
            parameter = new _Il2CppParameter(handle);
            accessor[parameter.name!] = parameter;
        }
        return accessor;
    }

    /**
     * @return Its static fixed offset, useful for static analysis.
     */
    @cache
    get relativePointerAsString(): string {
        return `0x${this.actualPointer.sub(library.base).toString(16).padStart(8, "0")}`;
    }

    /**
     * @return Its return type.
     */
    @cache
    get returnType(): _Il2CppType {
        return new _Il2CppType(Api._methodGetReturnType(this.handle));
    }

    /** @internal */
    @cache
    get nativeFunction(): NativeFunction {
        const parametersTypesAliasesForFrida = Array(this.parameterCount).fill("pointer");
        if (this.isInstance || unityVersion.isLegacy) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        if (this.isInflated) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        return new NativeFunction(this.actualPointer, this.returnType.aliasForFrida, parametersTypesAliasesForFrida);
    }

    /**
     * Abstraction over `Interceptor.replace`.
     * @param callback The new method implementation. `null` if you want to
     * revert it.
     */
    set implementation(callback: ImplementationCallback | null) {
        Interceptor.revert(this.actualPointer);

        if (callback == null) return;

        if (this.actualPointer.isNull()) {
            raise(`Can't replace method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
        }

        const parametersTypesAliasesForFrida = [];
        if (this.isInstance) {
            parametersTypesAliasesForFrida.push(this.class.type.aliasForFrida);
        }
        for (const parameterInfo of this.parameters) {
            parametersTypesAliasesForFrida.push(parameterInfo.type.aliasForFrida);
        }
        const methodInfo = this;

        const replaceCallback: NativeCallbackImplementation = function (...invocationArguments: any[]) {
            const instance = methodInfo.isInstance ? new _Il2CppObject(invocationArguments[0]) : null;
            const startIndex = +methodInfo.isInstance | +unityVersion.isLegacy;
            const args = methodInfo.parameters[filterAndMap](
                () => true,
                parameter => parameter.asHeld(invocationArguments, startIndex)
            );
            return callback.call(this!, instance, args);
        };

        const nativeCallback = new NativeCallback(replaceCallback, this.returnType.aliasForFrida, parametersTypesAliasesForFrida);

        Interceptor.replace(this.actualPointer, nativeCallback);
        Interceptor.flush();
    }

    /** @internal */
    @cache
    get parametersTypesAliasesForFrida(): string[] {
        const parametersTypesAliasesForFrida = new Array(this.parameterCount).fill("pointer");
        if (this.isInstance || unityVersion.isLegacy) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        if (this.isInflated) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        return parametersTypesAliasesForFrida;
    }

    /**
     * Invokes the method.
     * @param parameters The parameters required by the method.
     * @return A value, if any.
     */
    @shouldBeInstance(false)
    invoke<T extends AllowedType>(...parameters: AllowedType[]): T {
        return this._invoke(NULL, ...parameters) as T;
    }

    /**
     * Abstraction over `Interceptor.attach`.
     * @param onEnter The callback to execute when the method is invoked.
     * @param onLeave The callback to execute when the method is about to return.
     * @return Frida's `InvocationListener`.
     */
    intercept({ onEnter, onLeave }: { onEnter?: OnEnterCallback; onLeave?: OnLeaveCallback }): InvocationListener {
        if (this.actualPointer.isNull()) {
            raise(`Can't intercept method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
        }

        const interceptorCallbacks: ScriptInvocationListenerCallbacks = {};

        if (onEnter != undefined) {
            const methodInfo = this;
            interceptorCallbacks.onEnter = function (invocationArguments) {
                const instance = methodInfo.isInstance ? new _Il2CppObject(invocationArguments[0]) : null;
                const startIndex = +methodInfo.isInstance | +unityVersion.isLegacy;
                const args = methodInfo.parameters[filterAndMap](
                    () => true,
                    parameter => parameter.asHeld(invocationArguments, startIndex)
                );
                onEnter.call(this, instance, args);
            };
        }

        if (onLeave != undefined) {
            const methodInfo = this;
            interceptorCallbacks.onLeave = function (invocationReturnValue) {
                onLeave.call(this, {
                    valueHandle: invocationReturnValue.add(0),
                    get value() {
                        return readRawValue(invocationReturnValue, methodInfo.returnType);
                    },
                    set value(v) {
                        invocationReturnValue.replace(allocRawValue(v, methodInfo.returnType));
                    }
                } as Valuable);
            };
        }

        return Interceptor.attach(this.actualPointer, interceptorCallbacks);
    }

    /**
     * Prints a message when the method is invoked.
     */
    trace(): void {
        if (this.actualPointer.isNull()) {
            warn(`Can't trace method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
        }
        try {
            Interceptor.attach(this.actualPointer, () => inform(`${this.relativePointerAsString} ${this.name}`));
        } catch (e) {
            warn(`Can't trace method ${this.name} from ${this.class.type.name}: ${e.message}.`);
        }
    }

    /** @internal */
    @shouldBeInstance(true)
    asHeld(holder: NativePointer): Invokable {
        const invoke = this._invoke.bind(this, holder);
        return {
            invoke<T extends AllowedType>(...parameters: AllowedType[]): T {
                return invoke(...parameters) as T;
            }
        } as Invokable;
    }

    /** @internal */
    private _invoke(instance: NativePointer, ...parameters: AllowedType[]): AllowedType {
        if (this.parameterCount != parameters.length) {
            raise(`This method takes ${this.parameterCount} parameters, but ${parameters.length} were supplied.`);
        }
        const allocatedParameters = Array.from(this.parameters).map((parameter, i) => allocRawValue(parameters[i], parameter.type));

        if (this.isInstance || unityVersion.isLegacy) allocatedParameters.unshift(instance);
        if (this.isInflated) allocatedParameters.push(this.handle);

        return readRawValue(this.nativeFunction(...allocatedParameters) as NativePointer, this.returnType);
    }
}
