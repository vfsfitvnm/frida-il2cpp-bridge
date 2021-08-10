import { cache } from "decorator-cache-getter";

import { shouldBeInstance } from "../decorators";
import { fromFridaValue, toFridaValue } from "../utils";

import { addLevenshtein, overridePropertyValue } from "../../utils/utils";
import { raise, warn } from "../../utils/console";
import { NonNullNativeStruct } from "../../utils/native-struct";

/** Represents a `MethodInfo`. */
class Il2CppMethod extends NonNullNativeStruct {
    /** Gets the class in which this field is defined. */
    @cache
    get class(): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._methodGetClass(this));
    }

    /** */
    @cache
    get fridaSignature(): NativeCallbackArgumentType[] {
        const types = Object.values(this.parameters).map((parameter: Il2Cpp.Parameter) => parameter.type.fridaAlias);
        if (!this.isStatic || Il2Cpp.unityVersion.isBefore2018_3_0) {
            types.unshift("pointer"); // TODO or this.class.type.aliasForFrida?, check structs
        }
        if (this.isInflated) {
            types.unshift("pointer");
        }
        return types;
    }

    /** Determines whether this method is generic. */
    @cache
    get isGeneric(): boolean {
        return !!Il2Cpp.Api._methodIsGeneric(this);
    }

    /** Determines whether this method is inflated (generic with a concrete type parameter). */
    @cache
    get isInflated(): boolean {
        return !!Il2Cpp.Api._methodIsInflated(this);
    }

    /** Determines whether this method is static. */
    @cache
    get isStatic(): boolean {
        return !Il2Cpp.Api._methodIsInstance(this);
    }

    /** Gets the name of this method. */
    @cache
    get name(): string {
        return Il2Cpp.Api._methodGetName(this).readUtf8String()!;
    }

    /** @internal */
    @cache
    get nativeFunction(): NativeFunction<any, any> {
        return new NativeFunction(this.virtualAddress, this.returnType.fridaAlias, this.fridaSignature as NativeFunctionArgumentType[]);
    }

    /** Gets the encompassing object of the current method. */
    @cache
    get object(): Il2Cpp.Object {
        return new Il2Cpp.Object(Il2Cpp.Api._methodGetObject(this, NULL));
    }

    /** Gets the amount of parameters of this method. */
    @cache
    get parameterCount(): number {
        return Il2Cpp.Api._methodGetParamCount(this);
    }

    /** Gets the parameters of this method. */
    @cache
    get parameters(): Readonly<Record<string, Il2Cpp.Parameter>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor: Record<string, Il2Cpp.Parameter> = {};

        let handle: NativePointer;
        let parameter: Il2Cpp.Parameter;

        while (!(handle = Il2Cpp.Api._methodGetParameters(this, iterator)).isNull()) {
            parameter = new Il2Cpp.Parameter(handle);
            accessor[parameter.name!] = parameter;
        }

        return addLevenshtein(accessor);
    }

    /** Gets the relative virtual address (RVA) of this method. */
    @cache
    get relativeVirtualAddress(): NativePointer {
        return this.virtualAddress.sub(Il2Cpp.module.base);
    }

    /** Gets the return type of this method. */
    @cache
    get returnType(): Il2Cpp.Type {
        return new Il2Cpp.Type(Il2Cpp.Api._methodGetReturnType(this));
    }

    /** Gets the virtual address (VA) to this method. */
    @cache
    get virtualAddress(): NativePointer {
        return Il2Cpp.Api._methodGetPointer(this);
    }

    /** Replaces the body of this method. */
    set implementation(block: Il2Cpp.Method.Implementation) {
        if (this.virtualAddress.isNull()) {
            raise(`Skipping implementation for ${this.class.type.name}.${this.name}: pointer is null.`);
        }

        const replaceCallback: NativeCallbackImplementation<any, any> = (...args: any[]): any => {
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
            Interceptor.replace(
                this.virtualAddress,
                new NativeCallback(replaceCallback, this.returnType.fridaAlias, this.fridaSignature as NativeCallbackArgumentType[])
            );
        } catch (e) {
            warn(`Skipping implementation for ${this.class.type.name}.${this.name}: ${e.message}.`);
        }
    }

    /** Invokes this method. */
    @shouldBeInstance(false)
    invoke<T extends Il2Cpp.Method.ReturnType>(...parameters: Il2Cpp.Parameter.Type[]): T {
        return this.invokeRaw(NULL, ...parameters) as T;
    }

    /** @internal */
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

    /** */
    restoreImplementation(): void {
        Interceptor.revert(this.virtualAddress);
        Interceptor.flush();
    }

    /** @internal */
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

Il2Cpp.Method = Il2CppMethod;

declare global {
    namespace Il2Cpp {
        class Method extends Il2CppMethod {}
        namespace Method {
            type Implementation = (this: Il2Cpp.Class | Il2Cpp.Object, ...parameters: any[]) => Il2Cpp.Method.ReturnType;
            type ReturnType = void | Il2Cpp.Field.Type;
        }
    }
}
