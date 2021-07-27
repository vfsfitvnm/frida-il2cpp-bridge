import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp, shouldBeInstance } from "../decorators";
import { fromFridaValue, toFridaValue } from "../utils";

import { addLevenshtein, overridePropertyValue } from "../../utils/record";
import { raise, warn } from "../../utils/console";
import { NonNullNativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("Method")
class Il2CppMethod extends NonNullNativeStruct {
    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._methodGetClass(this));
    }

    @cache
    get fridaSignature(): NativeType[] {
        const types = Object.values(this.parameters).map((parameter: Il2Cpp.Parameter) => parameter.type.fridaAlias);
        if (!this.isStatic || Il2Cpp.unityVersion.isBefore2018_3_0) {
            types.unshift("pointer"); // TODO or this.class.type.aliasForFrida?, check structs
        }
        if (this.isInflated) {
            types.unshift("pointer");
        }
        return types;
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
    get nativeFunction(): NativeFunction {
        return new NativeFunction(this.virtualAddress, this.returnType.fridaAlias, this.fridaSignature);
    }

    @cache
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(Api._methodGetObject(this, NULL));
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
    get relativeVirtualAddress(): NativePointer {
        return this.virtualAddress.sub(Il2Cpp.module.base);
    }

    @cache
    get returnType(): Il2Cpp.Type {
        return new Il2Cpp.Type(Api._methodGetReturnType(this));
    }

    @cache
    get virtualAddress(): NativePointer {
        return Api._methodGetPointer(this);
    }

    set implementation(block: Il2Cpp.Method.Implementation) {
        if (this.virtualAddress.isNull()) {
            raise(`Skipping implementation for ${this.class.type.name}.${this.name}: pointer is null.`);
        }

        const replaceCallback: NativeCallbackImplementation = (...args: any[]): any => {
            const startIndex = +!this.isStatic | +Il2Cpp.unityVersion.isBefore2018_3_0;
            // TODO check inflated

            const result = block.call(
                this.isStatic ? this.class : overridePropertyValue(new Il2Cpp.Object(args[0]), "class", this.class),
                ...Object.values(this.parameters).map((parameter: Il2Cpp.Parameter, index: number) =>
                    fromFridaValue(args[index + startIndex], parameter.type)
                )
            );

            if (typeof result != "undefined") {
                return toFridaValue(result);
            }
        };

        this.restoreImplementation();
        try {
            Interceptor.replace(this.virtualAddress, new NativeCallback(replaceCallback, this.returnType.fridaAlias, this.fridaSignature));
        } catch (e) {
            warn(`Skipping implementation for ${this.class.type.name}.\x1b[1m${this.name}\x1b[0m (${e}).`);
        }
    }

    @shouldBeInstance(false)
    invoke<T extends Il2Cpp.Method.ReturnType>(...parameters: Il2Cpp.Parameter.Type[]): T {
        return this.invokeRaw(NULL, ...parameters) as T;
    }

    invokeRaw(instance: NativePointer, ...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Method.ReturnType {
        if (this.parameterCount != parameters.length) {
            raise(`This method takes ${this.parameterCount} parameters, but ${parameters.length} were supplied.`);
        }

        const allocatedParameters = Object.values(this.parameters).map((parameter: Il2Cpp.Parameter, index: number) =>
            toFridaValue(parameters[index])
        );

        if (!this.isStatic || Il2Cpp.unityVersion.isBefore2018_3_0) {
            allocatedParameters.unshift(instance);
        }
        if (this.isInflated) {
            allocatedParameters.push(this);
        }
        return fromFridaValue(this.nativeFunction(...allocatedParameters), this.returnType) as Il2Cpp.Method.ReturnType;
    }

    restoreImplementation(): void {
        Interceptor.revert(this.virtualAddress);
        Interceptor.flush();
    }

    @shouldBeInstance(true)
    withHolder(instance: Il2Cpp.Object): Il2Cpp.Method {
        return overridePropertyValue(
            new Il2Cpp.Method(this.handle),
            "invoke",
            <T extends Il2Cpp.Method.ReturnType>(...parameters: Il2Cpp.Parameter.Type[]): T => {
                return this.invokeRaw(instance.handle, ...parameters) as T;
            }
        );
    }
}
