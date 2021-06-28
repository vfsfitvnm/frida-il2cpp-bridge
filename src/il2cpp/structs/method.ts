import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp, shouldBeInstance } from "../decorators";
import { allocRawValue, readRawValue } from "../utils";

import { Accessor, filterAndMap } from "../../utils/accessor";
import { inform, raise, warn } from "../../utils/console";
import { NativeStructNotNull } from "../../utils/native-struct";
import { createNC } from "../../utils/extensions";

@injectToIl2Cpp("Method")
class Il2CppMethod extends NativeStructNotNull {
    @cache
    get actualPointer(): NativePointer {
        return Api._methodGetPointer(this.handle);
    }

    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._methodGetClass(this.handle));
    }

    @cache
    get isGeneric(): boolean {
        return Api._methodIsGeneric(this.handle);
    }

    @cache
    get isInflated(): boolean {
        return Api._methodIsInflated(this.handle);
    }

    @cache
    get isStatic(): boolean {
        return !Api._methodIsInstance(this.handle);
    }

    @cache
    get name(): string {
        return Api._methodGetName(this.handle)!;
    }

    @cache
    get parameterCount(): number {
        return Api._methodGetParamCount(this.handle);
    }

    @cache
    get parameters(): Accessor<Il2Cpp.Parameter> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<Il2Cpp.Parameter>();

        let handle: NativePointer;
        let parameter: Il2Cpp.Parameter;

        while (!(handle = Api._methodGetParameters(this.handle, iterator)).isNull()) {
            parameter = new Il2Cpp.Parameter(handle);
            accessor[parameter.name!] = parameter;
        }

        return accessor;
    }

    @cache
    get relativePointerAsString(): string {
        return `0x${this.actualPointer.sub(Il2Cpp.module.base).toString(16).padStart(8, "0")}`;
    }

    @cache
    get returnType(): Il2Cpp.Type {
        return new Il2Cpp.Type(Api._methodGetReturnType(this.handle));
    }

    /** @internal */
    @cache
    get nativeFunction(): NativeFunction {
        const parametersTypesAliasesForFrida = Array(this.parameterCount).fill("pointer");
        if (!this.isStatic || Il2Cpp.unityVersion.isLegacy) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        if (this.isInflated) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        return new NativeFunction(this.actualPointer, this.returnType.aliasForFrida, parametersTypesAliasesForFrida);
    }

    set implementation(callback: Il2Cpp.Method.ImplementationCallback | null) {
        Interceptor.revert(this.actualPointer);

        if (callback == null) {
            return;
        }

        if (this.actualPointer.isNull()) {
            raise(`Can't replace method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
        }

        const parametersTypesAliasesForFrida = [];
        if (!this.isStatic) {
            parametersTypesAliasesForFrida.push(this.class.type.aliasForFrida);
        }
        for (const parameterInfo of this.parameters) {
            parametersTypesAliasesForFrida.push(parameterInfo.type.aliasForFrida);
        }
        const methodInfo = this;

        const replaceCallback: NativeCallbackImplementation = function (...invocationArguments: any[]) {
            const instance = methodInfo.isStatic ? null : new Il2Cpp.Object(invocationArguments[0]);
            const startIndex = +!methodInfo.isStatic | +Il2Cpp.unityVersion.isLegacy;
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
        if (!this.isStatic || Il2Cpp.unityVersion.isLegacy) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        if (this.isInflated) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        return parametersTypesAliasesForFrida;
    }

    @shouldBeInstance(false)
    invoke<T extends Il2Cpp.AllowedType>(...parameters: Il2Cpp.AllowedType[]): T {
        return this.invokeRaw(NULL, ...parameters) as T;
    }

    invokeRaw(instance: NativePointer, ...parameters: Il2Cpp.AllowedType[]): Il2Cpp.AllowedType {
        if (this.parameterCount != parameters.length) {
            raise(`This method takes ${this.parameterCount} parameters, but ${parameters.length} were supplied.`);
        }
        const allocatedParameters = Array.from(this.parameters).map((parameter, i) => allocRawValue(parameters[i], parameter.type));

        if (!this.isStatic || Il2Cpp.unityVersion.isLegacy) {
            allocatedParameters.unshift(instance);
        }
        if (this.isInflated) {
            allocatedParameters.push(this.handle);
        }

        return readRawValue(this.nativeFunction(...allocatedParameters) as NativePointer, this.returnType);
    }

    intercept(callbacks: { onEnter?: Il2Cpp.Method.OnEnterCallback; onLeave?: Il2Cpp.Method.OnLeaveCallback }): InvocationListener {
        if (this.actualPointer.isNull()) {
            raise(`Can't intercept method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
        }

        const interceptorCallbacks: ScriptInvocationListenerCallbacks = {};

        if (callbacks.onEnter != undefined) {
            const methodInfo = this;
            interceptorCallbacks.onEnter = function (invocationArguments: InvocationArguments) {
                const instance = methodInfo.isStatic ? null : new Il2Cpp.Object(invocationArguments[0]);
                const startIndex = +!methodInfo.isStatic | +Il2Cpp.unityVersion.isLegacy;
                const args = methodInfo.parameters[filterAndMap](
                    () => true,
                    parameter => parameter.asHeld(invocationArguments, startIndex)
                );
                callbacks.onEnter!.call(this, instance, args);
            };
        }

        if (callbacks.onLeave != undefined) {
            const methodInfo = this;
            interceptorCallbacks.onLeave = function (invocationReturnValue: InvocationReturnValue) {
                callbacks.onLeave!.call(this, {
                    valueHandle: invocationReturnValue.add(0),
                    get value() {
                        return readRawValue(invocationReturnValue, methodInfo.returnType);
                    },
                    set value(v) {
                        invocationReturnValue.replace(allocRawValue(v, methodInfo.returnType));
                    }
                });
            };
        }

        return Interceptor.attach(this.actualPointer, interceptorCallbacks);
    }

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

    @shouldBeInstance(true)
    asHeld(holder: NativePointer): Il2Cpp.Invokable {
        const invoke = this.invokeRaw.bind(this, holder);
        return {
            invoke<T extends Il2Cpp.AllowedType>(...parameters: Il2Cpp.AllowedType[]): T {
                return invoke(...parameters) as T;
            }
        };
    }
}
