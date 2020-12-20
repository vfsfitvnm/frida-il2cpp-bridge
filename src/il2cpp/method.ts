import Api from "./api";
import { allocRawValue, AllowedType, Invokable, readRawValue, Valuable } from "./runtime";
import Il2CppParameter from "./parameter";
import Il2CppObject from "./object";
import { inform, raise, warn } from "../utils/console";
import { lazy } from "../utils/decorators";
import UnityVersion from "../utils/unity-version";
import { Accessor, filterAndMap } from "../utils/accessor";
import Il2CppClass from "./class";
import Il2CppType from "./type";

/** @internal */
export default class Il2CppMethod {
    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get actualPointer() {
        return Api._methodGetPointer(this.handle);
    }

    @lazy get class() {
        return new Il2CppClass(Api._methodGetClass(this.handle));
    }

    @lazy get isGeneric() {
        return Api._methodIsGeneric(this.handle);
    }

    @lazy get isInflated() {
        return Api._methodIsInflated(this.handle);
    }

    @lazy get isInstance() {
        return Api._methodIsInstance(this.handle);
    }

    @lazy get name() {
        return Api._methodGetName(this.handle)!;
    }

    @lazy get parameterCount() {
        return Api._methodGetParamCount(this.handle);
    }

    @lazy get parameters() {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<Il2CppParameter>();
        let handle: NativePointer;
        let parameter: Il2CppParameter;
        while (!(handle = Api._methodGetParameters(this.handle, iterator)).isNull()) {
            parameter = new Il2CppParameter(handle);
            accessor[parameter.name!] = parameter;
        }
        return accessor;
    }

    @lazy get relativePointerAsString() {
        return `0x${this.actualPointer.sub(Api._library.base).toString(16).padStart(8, "0")}`;
    }

    @lazy get returnType() {
        return new Il2CppType(Api._methodGetReturnType(this.handle));
    }

    @lazy get nativeFunction() {
        const parametersTypesAliasesForFrida = new Array(this.parameterCount).fill("pointer");
        if (this.isInstance || UnityVersion.CURRENT.isBelow("2018.3.0")) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        if (this.isInflated) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        return new NativeFunction(this.actualPointer, this.returnType.aliasForFrida, parametersTypesAliasesForFrida);
    }

    set implementation(callback: Il2CppImplementationCallback | null) {
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
            const instance = methodInfo.isInstance ? new Il2CppObject(invocationArguments[0]) : null;
            const startIndex = methodInfo.isInstance || UnityVersion.CURRENT.isBelow("2018.3.0") ? 1 : 0;
            const args = methodInfo.parameters[filterAndMap](
                () => true,
                parameter => parameter.asHeld(invocationArguments, startIndex)
            );
            return callback.call(this!, instance, args);
        };

        const nativeCallback = new NativeCallback(replaceCallback, this.returnType.aliasForFrida, parametersTypesAliasesForFrida);

        Interceptor.replace(this.actualPointer, nativeCallback);
    }

    @lazy get parametersTypesAliasesForFrida() {
        const parametersTypesAliasesForFrida = new Array(this.parameterCount).fill("pointer");
        if (this.isInstance || UnityVersion.CURRENT.isBelow("2018.3.0")) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        if (this.isInflated) {
            parametersTypesAliasesForFrida.push("pointer");
        }
        return parametersTypesAliasesForFrida;
    }

    invoke<T extends AllowedType>(...parameters: AllowedType[]) {
        if (this.isInstance) {
            raise(`Cannot invoke the instance method "${this.name}" without an instance.`);
        }
        return this._invoke(NULL, ...parameters);
    }

    intercept({ onEnter, onLeave }: { onEnter?: Il2CppOnEnterCallback; onLeave?: Il2CppOnLeaveCallback }) {
        if (this.actualPointer.isNull()) {
            raise(`Can't intercept method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
        }

        const interceptorCallbacks: ScriptInvocationListenerCallbacks = {};

        if (onEnter != undefined) {
            const methodInfo = this;
            interceptorCallbacks.onEnter = function (invocationArguments) {
                const instance = methodInfo.isInstance ? new Il2CppObject(invocationArguments[0]) : null;
                const startIndex = methodInfo.isInstance || UnityVersion.CURRENT.isBelow("2018.3.0") ? 1 : 0;
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

    asHeld(holder: NativePointer) {
        if (!this.isInstance) {
            raise(`"${this.name}" is a static method.`);
        }
        const invoke = this._invoke.bind(this, holder);
        return {
            invoke<T extends AllowedType>(...parameters: AllowedType[]) {
                return invoke(...parameters) as T;
            }
        } as Invokable;
    }

    private _invoke(instance: NativePointer, ...parameters: AllowedType[]) {
        if (this.parameterCount != parameters.length) {
            raise(`This method takes ${this.parameterCount} parameters, but ${parameters.length} were supplied.`);
        }
        const allocatedParameters = Array.from(this.parameters).map((parameter, i) => allocRawValue(parameters[i], parameter.type));

        if (this.isInstance || UnityVersion.CURRENT.isBelow("2018.3.0")) allocatedParameters.unshift(instance);
        if (this.isInflated) allocatedParameters.push(this.handle);

        return readRawValue(this.nativeFunction(...allocatedParameters) as NativePointer, this.returnType);
    }
}

/** @internal */
type Il2CppImplementationCallback = (this: InvocationContext, instance: Il2CppObject | null, parameters: Accessor<Valuable>) => AllowedType;

/** @internal */
type Il2CppOnEnterCallback = (this: InvocationContext, instance: Il2CppObject | null, parameters: Accessor<Valuable>) => void;

/** @internal */
type Il2CppOnLeaveCallback = (this: InvocationContext, returnValue: Valuable) => void;
