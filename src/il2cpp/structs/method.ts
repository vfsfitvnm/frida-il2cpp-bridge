import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp, shouldBeInstance } from "../decorators";
import { fromFridaValue, toFridaValue } from "../utils";

import { addLevenshtein, overridePropertyValue } from "../../utils/record";
import { raise } from "../../utils/console";
import { NonNullNativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("Method")
class Il2CppMethod extends NonNullNativeStruct {
    @cache
    get pointer(): NativePointer {
        return Api._methodGetPointer(this);
    }

    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._methodGetClass(this));
    }

    @cache
    get isGeneric(): boolean {
        return Api._methodIsGeneric(this);
    }

    @cache
    get isInflated(): boolean {
        return Api._methodIsInflated(this);
    }

    @cache
    get isStatic(): boolean {
        return !Api._methodIsInstance(this);
    }

    @cache
    get name(): string {
        return Api._methodGetName(this)!;
    }

    @cache
    get parameterCount(): number {
        return Api._methodGetParamCount(this);
    }

    @cache
    get parameters(): Readonly<Record<string, Il2Cpp.Parameter>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor: Record<string, Il2Cpp.Parameter> = {};

        let handle: NativePointer;
        let parameter: Il2Cpp.Parameter;

        while (!(handle = Api._methodGetParameters(this, iterator)).isNull()) {
            parameter = new Il2Cpp.Parameter(handle);
            accessor[parameter.name!] = parameter;
        }

        return addLevenshtein(accessor);
    }

    @cache
    get relativePointerAsString(): string {
        return `0x${this.pointer.sub(Il2Cpp.module.base).toString(16).padStart(8, "0")}`;
    }

    @cache
    get returnType(): Il2Cpp.Type {
        return new Il2Cpp.Type(Api._methodGetReturnType(this));
    }

    @cache
    get nativeFunction(): NativeFunction {
        return new NativeFunction(this.pointer, this.returnType.fridaAlias, this.fridaSignature);
    }

    set implementation(block: (this: Il2Cpp.Class | Il2Cpp.Object, ...parameters: any[]) => void | Il2Cpp.AllowedType) {
        if (this.pointer.isNull()) {
            raise(`Can't replace method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
        }

        const replaceCallback: NativeCallbackImplementation = (...args: any[]): any => {
            const startIndex = +!this.isStatic | +Il2Cpp.unityVersion.isLegacy;
            // TODO check inflated

            const result = block.call(
                this.isStatic ? this.class : overridePropertyValue(new Il2Cpp.Object(args[0]), "class", this.class),
                ...Object.values(this.parameters).map((parameter: Il2Cpp.Parameter, index: number) =>
                    fromFridaValue(args[index + startIndex], parameter.type)
                )
            );

            if (typeof result != "undefined") {
                return toFridaValue(result, this.returnType);
            }
        };

        Interceptor.replace(this.pointer, new NativeCallback(replaceCallback, this.returnType.fridaAlias, this.fridaSignature));
    }

    @cache
    get fridaSignature(): string[] {
        const types = Object.values(this.parameters).map((parameter: Il2Cpp.Parameter) => parameter.type.fridaAlias);
        if (!this.isStatic || Il2Cpp.unityVersion.isLegacy) {
            types.unshift("pointer"); // or this.class.type.aliasForFrida?
        }
        if (this.isInflated) {
            types.unshift("pointer");
        }
        return types;
    }

    @shouldBeInstance(false)
    invoke<T extends Il2Cpp.AllowedType>(...parameters: Il2Cpp.AllowedType[]): T {
        return this.invokeRaw(NULL, ...parameters) as T;
    }

    invokeRaw(instance: NativePointer, ...parameters: Il2Cpp.AllowedType[]): Il2Cpp.AllowedType {
        if (this.parameterCount != parameters.length) {
            raise(`This method takes ${this.parameterCount} parameters, but ${parameters.length} were supplied.`);
        }

        const allocatedParameters = Object.values(this.parameters).map((parameter: Il2Cpp.Parameter, index: number) =>
            toFridaValue(parameters[index], parameter.type)
        );

        if (!this.isStatic || Il2Cpp.unityVersion.isLegacy) {
            allocatedParameters.unshift(instance);
        }
        if (this.isInflated) {
            allocatedParameters.push(this);
        }
        return fromFridaValue(this.nativeFunction(...allocatedParameters), this.returnType);
    }

    restoreImplementation(): void {
        Interceptor.revert(this.pointer);
    }

    @shouldBeInstance(true)
    asHeld(holder: NativePointer): Il2Cpp.Invokable {
        const invoke = this.invokeRaw.bind(this, holder);
        return {
            invoke<T extends Il2Cpp.AllowedType>(...parameters: Il2Cpp.AllowedType[]): T {
                return invoke(...parameters) as T;
            }
        } as Il2Cpp.Invokable;
    }
}
