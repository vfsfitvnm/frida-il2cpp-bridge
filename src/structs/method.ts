namespace Il2Cpp {
    export class Method<T extends Il2Cpp.Method.ReturnType = Il2Cpp.Method.ReturnType> extends NativeStruct {
        /** Gets the class in which this method is defined. */
        @lazy
        get class(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.api.methodGetClass(this));
        }

        /** Gets the flags of the current method. */
        @lazy
        get flags(): number {
            return Il2Cpp.api.methodGetFlags(this, NULL);
        }

        /** Gets the implementation flags of the current method. */
        @lazy
        get implementationFlags(): number {
            const implementationFlagsPointer = Memory.alloc(Process.pointerSize);
            Il2Cpp.api.methodGetFlags(this, implementationFlagsPointer);

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

        /** Gets the generic parameters of this generic method. */
        @lazy
        get generics(): Il2Cpp.Class[] {
            if (!this.isGeneric && !this.isInflated) {
                return [];
            }

            const types = this.object.method<Il2Cpp.Array<Il2Cpp.Object>>("GetGenericArguments").invoke();
            return globalThis.Array.from(types).map(_ => new Il2Cpp.Class(Il2Cpp.api.classFromObject(_)));
        }

        /** Determines whether this method is external. */
        @lazy
        get isExternal(): boolean {
            return (this.implementationFlags & Il2Cpp.Method.ImplementationAttribute.InternalCall) != 0;
        }

        /** Determines whether this method is generic. */
        @lazy
        get isGeneric(): boolean {
            return !!Il2Cpp.api.methodIsGeneric(this);
        }

        /** Determines whether this method is inflated (generic with a concrete type parameter). */
        @lazy
        get isInflated(): boolean {
            return !!Il2Cpp.api.methodIsInflated(this);
        }

        /** Determines whether this method is static. */
        @lazy
        get isStatic(): boolean {
            return !Il2Cpp.api.methodIsInstance(this);
        }

        /** Determines whether this method is synchronized. */
        @lazy
        get isSynchronized(): boolean {
            return (this.implementationFlags & Il2Cpp.Method.ImplementationAttribute.Synchronized) != 0;
        }

        /** Gets the access modifier of this method. */
        @lazy
        get modifier(): string | undefined {
            switch (this.flags & Il2Cpp.Method.Attributes.MemberAccessMask) {
                case Il2Cpp.Method.Attributes.Private:
                    return "private";
                case Il2Cpp.Method.Attributes.FamilyAndAssembly:
                    return "private protected";
                case Il2Cpp.Method.Attributes.Assembly:
                    return "internal";
                case Il2Cpp.Method.Attributes.Family:
                    return "protected";
                case Il2Cpp.Method.Attributes.FamilyOrAssembly:
                    return "protected internal";
                case Il2Cpp.Method.Attributes.Public:
                    return "public";
            }
        }

        /** Gets the name of this method. */
        @lazy
        get name(): string {
            return Il2Cpp.api.methodGetName(this).readUtf8String()!;
        }

        /** @internal */
        @lazy
        get nativeFunction(): NativeFunction<any, any> {
            return new NativeFunction(this.virtualAddress, this.returnType.fridaAlias, this.fridaSignature as NativeFunctionArgumentType[]);
        }

        /** Gets the encompassing object of the current method. */
        @lazy
        get object(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.api.methodGetObject(this, NULL));
        }

        /** Gets the amount of parameters of this method. */
        @lazy
        get parameterCount(): number {
            return Il2Cpp.api.methodGetParameterCount(this);
        }

        /** Gets the parameters of this method. */
        @lazy
        get parameters(): Il2Cpp.Parameter[] {
            return globalThis.Array.from(globalThis.Array(this.parameterCount), (_, i) => {
                const parameterName = Il2Cpp.api.methodGetParameterName(this, i).readUtf8String()!;
                const parameterType = Il2Cpp.api.methodGetParameterType(this, i);
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
            return new Il2Cpp.Type(Il2Cpp.api.methodGetReturnType(this));
        }

        /** Gets the virtual address (VA) of this method. */
        get virtualAddress(): NativePointer {
            const FilterTypeName = Il2Cpp.corlib.class("System.Reflection.Module").initialize().field<Il2Cpp.Object>("FilterTypeName").value;
            const FilterTypeNameMethodPointer = FilterTypeName.field<NativePointer>("method_ptr").value;
            const FilterTypeNameMethod = FilterTypeName.field<NativePointer>("method").value;

            // prettier-ignore
            const offset = FilterTypeNameMethod.offsetOf(_ => _.readPointer().equals(FilterTypeNameMethodPointer)) 
                ?? raise("couldn't find the virtual address offset in the native method struct");

            // prettier-ignore
            getter(Il2Cpp.Method.prototype, "virtualAddress", function (this: Il2Cpp.Method) {
                return this.handle.add(offset).readPointer();
            }, lazy);

            // In Unity 2017.4.40f1 (don't know about others),
            // `Il2Cpp.Class::initialize` somehow triggers a nasty bug during
            // early instrumentation, so that we aren't able to obtain the
            // offset to get the virtual address of a method when the script
            // is reloaded. A workaround consists in manually re-invoking the
            // static constructor.
            Il2Cpp.corlib.class("System.Reflection.Module").method(".cctor").invoke();

            return this.virtualAddress;
        }

        /** Replaces the body of this method. */
        set implementation(block: (this: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.ValueType, ...parameters: Il2Cpp.Parameter.Type[]) => T) {
            try {
                Interceptor.replace(this.virtualAddress, this.wrap(block));
            } catch (e: any) {
                switch (e.message) {
                    case "access violation accessing 0x0":
                        raise(`couldn't set implementation for method ${this.name} as it has a NULL virtual address`);
                    case /unable to intercept function at \w+; please file a bug/.exec(e.message)?.input:
                        warn(`couldn't set implementation for method ${this.name} as it may be a thunk`);
                        break;
                    case "already replaced this function":
                        warn(`couldn't set implementation for method ${this.name} as it has already been replaced by a thunk`);
                        break;
                    default:
                        throw e;
                }
            }
        }

        /** Creates a generic instance of the current generic method. */
        inflate<R extends Il2Cpp.Method.ReturnType = T>(...classes: Il2Cpp.Class[]): Il2Cpp.Method<R> {
            if (!this.isGeneric) {
                raise(`cannot inflate method ${this.name} as it has no generic parameters`);
            }

            if (this.generics.length != classes.length) {
                raise(`cannot inflate method ${this.name} as it needs ${this.generics.length} generic parameter(s), not ${classes.length}`);
            }

            const types = classes.map(_ => _.type.object);
            const typeArray = Il2Cpp.array(Il2Cpp.corlib.class("System.Type"), types);

            const inflatedMethodObject = this.object.method<Il2Cpp.Object>("MakeGenericMethod", 1).invoke(typeArray);
            return new Il2Cpp.Method(inflatedMethodObject.field<NativePointer>("mhandle").value);
        }

        /** Invokes this method. */
        invoke(...parameters: Il2Cpp.Parameter.Type[]): T {
            if (!this.isStatic) {
                raise(`cannot invoke non-static method ${this.name} as it must be invoked throught a Il2Cpp.Object, not a Il2Cpp.Class`);
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
                    raise("an unexpected native invocation exception occurred, this is due to parameter types mismatch");
                }

                switch (e.message) {
                    case "bad argument count":
                        raise(`couldn't invoke method ${this.name} as it needs ${this.parameterCount} parameter(s), not ${parameters.length}`);
                    case "expected a pointer":
                    case "expected number":
                    case "expected array with fields":
                        raise(`couldn't invoke method ${this.name} using incorrect parameter types`);
                }

                throw e;
            }
        }

        /** Gets the overloaded method with the given parameter types. */
        overload(...parameterTypes: string[]): Il2Cpp.Method<T> {
            const result = this.tryOverload<T>(...parameterTypes);

            if (result != undefined) return result;

            raise(`couldn't find overloaded method ${this.name}(${parameterTypes})`);
        }

        /** Gets the parameter with the given name. */
        parameter(name: string): Il2Cpp.Parameter {
            return this.tryParameter(name) ?? raise(`couldn't find parameter ${name} in method ${this.name}`);
        }

        /** Restore the original method implementation. */
        revert(): void {
            Interceptor.revert(this.virtualAddress);
            Interceptor.flush();
        }

        /** Gets the overloaded method with the given parameter types. */
        tryOverload<U extends Il2Cpp.Method.ReturnType = T>(...parameterTypes: string[]): Il2Cpp.Method<U> | undefined {
            let klass: Il2Cpp.Class | null = this.class;
            while (klass) {
                const method = klass.methods.find(method => {
                    return (
                      method.name == this.name &&
                      method.parameterCount == parameterTypes.length &&
                      method.parameters.every((e, i) => e.type.name == parameterTypes[i])
                    );
                }) as Il2Cpp.Method<U> | undefined;
                if (method) {
                    return method;
                }
                klass = klass.parent;
            }
            return undefined;
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
        withHolder(instance: Il2Cpp.Object | Il2Cpp.ValueType): Il2Cpp.Method<T> {
            if (this.isStatic) {
                raise(`cannot access static method ${this.class.type.name}::${this.name} from an object, use a class instead`);
            }

            return new Proxy(this, {
                get(target: Il2Cpp.Method<T>, property: keyof Il2Cpp.Method<T>): any {
                    switch (property) {
                        case "invoke":
                            // In Unity 5.3.5f1 and >= 2021.2.0f1, value types
                            // methods may assume their `this` parameter is a
                            // pointer to raw data (that is how value types are
                            // layed out in memory) instead of a pointer to an
                            // object (that is object header + raw data).
                            // In any case, they also don't use whatever there
                            // is in the object header, so we can safely "skip"
                            // the object header by adding the object header
                            // size to the object (a boxed value type) handle.
                            const handle =
                                instance instanceof Il2Cpp.ValueType
                                    ? target.class.isValueType
                                        ? instance.handle.add(maybeObjectHeaderSize() - Il2Cpp.Object.headerSize)
                                        : raise(`cannot invoke method ${target.class.type.name}::${target.name} against a value type, you must box it first`)
                                    : target.class.isValueType
                                    ? instance.handle.add(maybeObjectHeaderSize())
                                    : instance.handle;

                            return target.invokeRaw.bind(target, handle);
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

        /** @internal */
        wrap(block: (this: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.ValueType, ...parameters: Il2Cpp.Parameter.Type[]) => T): NativeCallback<any, any> {
            const startIndex = +!this.isStatic | +Il2Cpp.unityVersionIsBelow201830;
            return new NativeCallback(
                (...args: NativeCallbackArgumentValue[]): NativeCallbackReturnValue => {
                    const thisObject = this.isStatic
                        ? this.class
                        : this.class.isValueType
                        ? new Il2Cpp.ValueType((args[0] as NativePointer).add(Il2Cpp.Object.headerSize - maybeObjectHeaderSize()), this.class.type)
                        : new Il2Cpp.Object(args[0] as NativePointer);

                    const parameters = this.parameters.map((_, i) => fromFridaValue(args[i + startIndex], _.type));
                    const result = block.call(thisObject, ...parameters);
                    return toFridaValue(result);
                },
                this.returnType.fridaAlias,
                this.fridaSignature
            );
        }
    }

    let maybeObjectHeaderSize = (): number => {
        const struct = Il2Cpp.corlib.class("System.RuntimeTypeHandle").initialize().alloc();
        struct.method(".ctor").invokeRaw(struct, ptr(0xdeadbeef));

        // Here we check where the sentinel value is
        // if it's not where it is supposed to be, it means struct methods
        // assume they are receiving value types (that is a pointer to raw data)
        // hence, we must "skip" the object header when invoking such methods.
        const offset = struct.field<NativePointer>("value").value.equals(ptr(0xdeadbeef)) ? 0 : Il2Cpp.Object.headerSize;
        return (maybeObjectHeaderSize = () => offset)();
    };

    export namespace Method {
        export type ReturnType = void | Il2Cpp.Field.Type;

        export const enum Attributes {
            MemberAccessMask = 0x0007,
            PrivateScope = 0x0000,
            Private = 0x0001,
            FamilyAndAssembly = 0x0002,
            Assembly = 0x0003,
            Family = 0x0004,
            FamilyOrAssembly = 0x0005,
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
