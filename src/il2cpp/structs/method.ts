namespace Il2Cpp {
    export class Method<T extends Il2Cpp.Method.ReturnType = Il2Cpp.Method.ReturnType> extends NonNullNativeStruct {
        /** Gets the class in which this method is defined. */
        @lazy
        get class(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.Api._methodGetClass(this));
        }

        /** Gets the flags of the current method. */
        @lazy
        get flags(): number {
            return Il2Cpp.Api._methodGetFlags(this, NULL);
        }

        /** Gets the implementation flags of the current method. */
        @lazy
        get implementationFlags(): number {
            const implementationFlagsPointer = Memory.alloc(Process.pointerSize);
            Il2Cpp.Api._methodGetFlags(this, implementationFlagsPointer);

            return implementationFlagsPointer.readU32();
        }

        /** */
        @lazy
        get fridaSignature(): NativeCallbackArgumentType[] {
            const types: NativeCallbackArgumentType[] = [];

            for (const parameter of this.parameters) {
                types.push(parameter.type.fridaAlias);
            }

            if (!this.isStatic || Il2Cpp.unityVersionIsBelow201830) {
                types.unshift("pointer");
            }

            if (this.isInflated) {
                types.push("pointer");
            }

            return types;
        }

        /** Gets the amount of generic parameters of this generic method. */
        @lazy
        get genericParameterCount(): number {
            if (!this.isGeneric) {
                return 0;
            }

            return this.object.method<Il2Cpp.Array>("GetGenericArguments").invoke().length;
        }

        /** Determines whether this method is external. */
        @lazy
        get isExternal(): boolean {
            return !!Il2Cpp.Api._methodIsExternal(this);
        }

        /** Determines whether this method is generic. */
        @lazy
        get isGeneric(): boolean {
            return !!Il2Cpp.Api._methodIsGeneric(this);
        }

        /** Determines whether this method is inflated (generic with a concrete type parameter). */
        @lazy
        get isInflated(): boolean {
            return !!Il2Cpp.Api._methodIsInflated(this);
        }

        /** Determines whether this method is static. */
        @lazy
        get isStatic(): boolean {
            return !Il2Cpp.Api._methodIsInstance(this);
        }

        /** Determines whether this method is synchronized. */
        @lazy
        get isSynchronized(): boolean {
            return !!Il2Cpp.Api._methodIsSynchronized(this);
        }

        /** Gets the access modifier of this method. */
        @lazy
        get modifier(): string {
            return Il2Cpp.Api._methodGetModifier(this).readUtf8String()!;
        }

        /** Gets the name of this method. */
        @lazy
        get name(): string {
            return Il2Cpp.Api._methodGetName(this).readUtf8String()!;
        }

        /** @internal */
        @lazy
        get nativeFunction(): NativeFunction<any, any> {
            return new NativeFunction(this.virtualAddress, this.returnType.fridaAlias, this.fridaSignature as NativeFunctionArgumentType[]);
        }

        /** Gets the encompassing object of the current method. */
        @lazy
        get object(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.Api._methodGetObject(this, NULL));
        }

        /** Gets the amount of parameters of this method. */
        @lazy
        get parameterCount(): number {
            return Il2Cpp.Api._methodGetParameterCount(this);
        }

        /** Gets the parameters of this method. */
        @lazy
        get parameters(): Il2Cpp.Parameter[] {
            return globalThis.Array.from(globalThis.Array(this.parameterCount), (_, i) => {
                const parameterName = Il2Cpp.Api._methodGetParameterName(this, i).readUtf8String()!;
                const parameterType = Il2Cpp.Api._methodGetParameterType(this, i);
                return new Il2Cpp.Parameter(parameterName, i, new Il2Cpp.Type(parameterType));
            });
        }

        /** Gets the relative virtual address (RVA) of this method. */
        @lazy
        get relativeVirtualAddress(): NativePointer {
            return this.virtualAddress.sub(Il2Cpp.module.base);
        }

        /** Gets the return type of this method. */
        @lazy
        get returnType(): Il2Cpp.Type {
            return new Il2Cpp.Type(Il2Cpp.Api._methodGetReturnType(this));
        }

        /** Gets the virtual address (VA) to this method. */
        @lazy
        get virtualAddress(): NativePointer {
            return Il2Cpp.Api._methodGetPointer(this);
        }

        /** Replaces the body of this method. */
        set implementation(block: (this: Il2Cpp.Class | Il2Cpp.Object, ...parameters: any[]) => T) {
            const startIndex = +!this.isStatic | +Il2Cpp.unityVersionIsBelow201830;

            const callback = (...args: any[]): any => {
                const parameters = this.parameters.map((e, i) => fromFridaValue(args[i + startIndex], e.type));
                return toFridaValue(block.call(this.isStatic ? this.class : new Il2Cpp.Object(args[0]), ...parameters) as any);
            };

            try {
                Interceptor.replace(this.virtualAddress, new NativeCallback(callback, this.returnType.fridaAlias, this.fridaSignature));
            } catch (e: any) {
                switch (e.message) {
                    case "access violation accessing 0x0":
                        raise(`cannot implement method ${this.name}: it has a NULL virtual address`);
                    case `unable to intercept function at ${this.virtualAddress}; please file a bug`:
                        warn(`cannot implement method ${this.name}: it may be a thunk`);
                        break;
                    case "already replaced this function":
                        warn(`cannot implement method ${this.name}: already replaced by a thunk`);
                        break;
                    default:
                        throw e;
                }
            }
        }

        /** Creates a generic instance of the current generic method. */
        inflate<R extends Il2Cpp.Method.ReturnType = T>(...classes: Il2Cpp.Class[]): Il2Cpp.Method<R> {
            if (!this.isGeneric) {
                raise(`cannot inflate method ${this.name}: it has no generic parameters`);
            }

            if (this.genericParameterCount != classes.length) {
                raise(`cannot inflate method ${this.name}: it needs ${this.genericParameterCount} generic parameter(s), not ${classes.length}`);
            }

            const types = classes.map(_ => _.type.object);
            const typeArray = Il2Cpp.Array.from(Il2Cpp.Image.corlib.class("System.Type"), types);

            const inflatedMethodObject = this.object.method<Il2Cpp.Object>("MakeGenericMethod", 1).invoke(typeArray);
            return new Il2Cpp.Method(Il2Cpp.Api._methodGetFromReflection(inflatedMethodObject));
        }

        /** Invokes this method. */
        invoke(...parameters: Il2Cpp.Parameter.Type[]): T {
            if (!this.isStatic) {
                raise(`cannot invoke a non-static method ${this.name}: must be invoked throught a Il2Cpp.Object, not a Il2Cpp.Class`);
            }
            return this.invokeRaw(NULL, ...parameters);
        }

        /** @internal */
        invokeRaw(instance: NativePointerValue, ...parameters: Il2Cpp.Parameter.Type[]): T {
            const allocatedParameters = parameters.map(toFridaValue);

            if (!this.isStatic || Il2Cpp.unityVersionIsBelow201830) {
                allocatedParameters.unshift(instance);
            }

            if (this.isInflated) {
                allocatedParameters.push(this.handle);
            }

            try {
                const returnValue = this.nativeFunction(...allocatedParameters);
                return fromFridaValue(returnValue, this.returnType) as T;
            } catch (e: any) {
                if (e == null) {
                    raise("an unexpected native function exception occurred, this is due to parameter types mismatch");
                }

                switch (e.message) {
                    case "bad argument count":
                        raise(`cannot invoke method ${this.name}: it needs ${this.parameterCount} parameter(s), not ${parameters.length}`);
                    case "expected a pointer":
                    case "expected number":
                    case "expected array with fields":
                        raise(`cannot invoke method ${this.name}: parameter types mismatch`);
                }

                throw e;
            }
        }

        /** Gets the overloaded method with the given parameter types. */
        overload(...parameterTypes: string[]): Il2Cpp.Method<T> {
            const result = this.tryOverload<T>(...parameterTypes);

            if (result != undefined) return result;

            raise(`cannot find overloaded method ${this.name}(${parameterTypes})`);
        }

        /** Gets the parameter with the given name. */
        parameter(name: string): Il2Cpp.Parameter {
            // prettier-ignore
            return this.tryParameter(name) ?? keyNotFound(name, this.name, this.parameters.map(_ => _.name));
        }

        /** Restore the original method implementation. */
        revert(): void {
            Interceptor.revert(this.virtualAddress);
            Interceptor.flush();
        }

        /** Gets the overloaded method with the given parameter types. */
        tryOverload<U extends Il2Cpp.Method.ReturnType = T>(...parameterTypes: string[]): Il2Cpp.Method<U> | undefined {
            return this.class.methods.find(method => {
                return (
                    method.name == this.name &&
                    method.parameterCount == parameterTypes.length &&
                    method.parameters.every((e, i) => e.type.name == parameterTypes[i])
                );
            }) as Il2Cpp.Method<U> | undefined;
        }

        /** Gets the parameter with the given name. */
        tryParameter(name: string): Il2Cpp.Parameter | undefined {
            return this.parameters.find(_ => _.name == name);
        }

        /** */
        toString(): string {
            return `\
${this.isStatic ? `static ` : ``}\
${this.returnType.name} \
${this.name}\
(${this.parameters.join(`, `)});\
${this.virtualAddress.isNull() ? `` : ` // 0x${this.relativeVirtualAddress.toString(16).padStart(8, `0`)}`}`;
        }

        /** @internal */
        withHolder(instance: Il2Cpp.Object): Il2Cpp.Method<T> {
            return new Proxy(this, {
                get(target: Il2Cpp.Method<T>, property: keyof Il2Cpp.Method<T>): any {
                    switch (property) {
                        case "invoke":
                            return target.invokeRaw.bind(target, instance.handle);
                        case "inflate":
                        case "overload":
                        case "tryOverload":
                            return function (...args: any[]) {
                                return target[property](...args)?.withHolder(instance);
                            };
                    }

                    return Reflect.get(target, property);
                }
            });
        }
    }

    export namespace Method {
        export type ReturnType = void | Il2Cpp.Field.Type;

        export const enum Attributes {
            MemberAccessMask = 0x0007,
            PrivateScope = 0x0000,
            Private = 0x0001,
            FamANDAssem = 0x0002,
            Assembly = 0x0003,
            Family = 0x0004,
            FamORAssem = 0x0005,
            Public = 0x0006,
            Static = 0x0010,
            Final = 0x0020,
            Virtual = 0x0040,
            HideBySig = 0x0080,
            CheckAccessOnOverride = 0x0200,
            VtableLayoutMask = 0x0100,
            ReuseSlot = 0x0000,
            NewSlot = 0x0100,
            Abstract = 0x0400,
            SpecialName = 0x0800,
            PinvokeImpl = 0x2000,
            UnmanagedExport = 0x0008,
            RTSpecialName = 0x1000,
            ReservedMask = 0xd000,
            HasSecurity = 0x4000,
            RequireSecObject = 0x8000
        }

        export const enum ImplementationAttribute {
            CodeTypeMask = 0x0003,
            IntermediateLanguage = 0x0000,
            Native = 0x0001,
            OptimizedIntermediateLanguage = 0x0002,
            Runtime = 0x0003,
            ManagedMask = 0x0004,
            Unmanaged = 0x0004,
            Managed = 0x0000,
            ForwardRef = 0x0010,
            PreserveSig = 0x0080,
            InternalCall = 0x1000,
            Synchronized = 0x0020,
            NoInlining = 0x0008,
            AggressiveInlining = 0x0100,
            NoOptimization = 0x0040,
            SecurityMitigations = 0x0400,
            MaxMethodImplVal = 0xffff
        }
    }
}
