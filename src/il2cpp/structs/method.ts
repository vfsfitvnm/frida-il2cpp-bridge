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
 * ```typescript
 * const mscorlib = Il2Cpp.domain.assemblies.mscorlib.image;
 * //
 * const BooleanClass = mscorlib.classes["System.Boolean"];
 * const Int32Class = mscorlib.classes["System.Int32"];
 * const TupleClass = mscorlib.classes["System.Tuple"];
 * const MathClass = mscorlib.classes["System.Math"];
 * const ArrayClass = mscorlib.classes["System.Array"];
 * //
 * assert(MathClass.methods.Sqrt.class.handle.equals(MathClass.handle));
 * //
 * assert(ArrayClass.methods.Empty.isGeneric);
 * //
 * assert(BooleanClass.methods.ToString.isInstance);
 * assert(!BooleanClass.methods.Parse.isInstance);
 * //
 * assert(MathClass.methods.Sqrt.name == "Sqrt");
 * //
 * assert(MathClass.methods[".cctor"].parameterCount == 0);
 * assert(MathClass.methods.Abs.parameterCount == 1);
 * assert(MathClass.methods.Max.parameterCount == 2);
 * //
 * assert(TupleClass.methods.CombineHashCodes.returnType.class.handle.equals(Int32Class.handle));
 * //
 * assert(BooleanClass.methods.Parse.invoke<boolean>(Il2Cpp.String.from("true")));
 * ```
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
    @cache get actualPointer() {
        return Api._methodGetPointer(this.handle);
    }

    /**
     * @return The class it belongs to.
     */
    @cache get class() {
        return new _Il2CppClass(Api._methodGetClass(this.handle));
    }

    /**
     * @return `true` if it's generic, `false` otherwise.
     */
    @cache get isGeneric() {
        return Api._methodIsGeneric(this.handle);
    }

    /**
     * @return `true` if it's inflated (a generic with a concrete type parameter),
     * false otherwise.
     */
    @cache get isInflated() {
        return Api._methodIsInflated(this.handle);
    }

    /**
     *  @return `true` if it's an instance method, `false` otherwise.
     */
    @cache get isInstance() {
        return Api._methodIsInstance(this.handle);
    }

    /**
     * @return Its name.
     */
    @cache get name() {
        return Api._methodGetName(this.handle)!;
    }

    /**
     * @return The count of its parameters.
     */
    @cache get parameterCount() {
        return Api._methodGetParamCount(this.handle);
    }

    /**
     * We can iterate over the parameters using a `for..of` loop,
     * or access a specific parameter using its name.
     * ```typescript
     * const Compare = mscorlib.classes["System.String"].methods.Compare;
     * for (const parameter of Compare.parameters) {
     * }
     * const strA = Compare.strA;
     * ```
     * @return Its parameters.
     */
    @cache get parameters() {
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
    @cache get relativePointerAsString() {
        return `0x${this.actualPointer.sub(library.base).toString(16).padStart(8, "0")}`;
    }

    /**
     * @return Its return type.
     */
    @cache get returnType() {
        return new _Il2CppType(Api._methodGetReturnType(this.handle));
    }

    /** @internal */
    @cache get nativeFunction() {
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
     * ```typescript
     * const MathClass = mscorlib.classes["System.Math"];
     * MathClass.methods.Max.implementation = (instance, parameters) => {
     *     const realMax = Math.max(parameters.val1.value, parameters.val2.value);
     *     return !realMax;
     * }
     * ```
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
    }

    /** @internal */
    @cache get parametersTypesAliasesForFrida() {
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
     * ```typescript
     * const CoreModule = domain.assemblies["UnityEngine.CoreModule"].image;
     * const Application = CoreModule.classes["UnityEngine.Application"];
     * const get_identifier = ApplicationC.methods.get_identifier;
     * const result = get_identifier.invoke<Il2Cpp.String>();
     * assert(result.content == "com.example.application");
     * ```
     * @param parameters The parameters required by the method.
     * @return A value, if any.
     */
    @shouldBeInstance(false)
    invoke<T extends AllowedType>(...parameters: AllowedType[]): T {
        return this._invoke(NULL, ...parameters) as T;
    }

    /**
     * Abstraction over `Interceptor.attach`.
     * ```typescript
     * const StringComparer = mscorlib.classes["System.StringComparer"];
     * StringComparer.methods.Compare_1.intercept({
     *     onEnter(instance, parameters) {
     *         assert(instance == null);
     *         assert(parameters.x.type.name == "System.String");
     *         assert(parameters.y.type.name == "System.String");
     *         (parameters.y.value as Il2Cpp.String).content = "same instance, new content";
     *         parameters.y.value = Il2Cpp.String("new instance, new content");
     *     },
     *     onLeave(returnValue) {
     *         returnValue.value = returnValue.value * -1;
     *     }
     * });
     * ```
     * @param onEnter The callback to execute when the method is invoked.
     * @param onLeave The callback to execute when the method is about to return.
     * @return Frida's `InvocationListener`.
     */
    intercept({ onEnter, onLeave }: { onEnter?: OnEnterCallback; onLeave?: OnLeaveCallback }) {
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
    trace() {
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
    asHeld(holder: NativePointer) {
        const invoke = this._invoke.bind(this, holder);
        return {
            invoke<T extends AllowedType>(...parameters: AllowedType[]) {
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
