declare global {
    /**
     * Everything is exposed through this global object.\
     * Every `Il2Cpp.${...}` class has a `handle` property, which is its `NativePointer`.
     */
    namespace Il2Cpp {
        /**
         * The Unity version of the current application.
         */
        const unityVersion: string;

        /**
         * The whole thing must be initialized first.
         * This is potentially asynchronous because
         * the `IL2CPP` library could be loaded at any
         * time, so we just make sure it's loaded.
         * The current Unity version will also be
         * detected.
         * ```typescript
         * import "frida-il2cpp-bridge";
         * async function main() {
         *   await Il2Cpp.initialize();
         *   console.log(Il2Cpp.unityVersion);
         * }
         * main().catch(error => console.log(error.stack));
         ```
         */
        function initialize(): Promise<void>;

        /**
         * Performs a dump of the assemblies.
         * ```typescript
         * const Application = domain.assemblies["UnityEngine.CoreModule"].image.classes["UnityEngine.Application"];
         * const version = Application.methods.get_version.invoke();
         * const identifier = Application.methods.get_identifier.invoke();
         * const persistentDataPath = Application.methods.get_persistentDataPath.invoke();
         * Il2Cpp.dump(`${persistentDataPath}/${identifier}_${version}.cs`);
         * ```
         * @param fullPathName Where to save the dump. The caller has to
         * make sure the application has a write permission for that location.
         *
         */
        function dump(fullPathName: string): Promise<void>;

        /**
         * It reads the GC descriptor of the given class and looks for its objects
         * on the heap. During this process, it may stop and start the GC world
         * multiple times.\
         * A version with callbacks is not really needed because:
         * - There aren't performance issues;
         * - It cannot be stopped;
         * - The `onMatch` callback can only be called when the GC world starts again,
         * but the whole thing is enough fast it doesn't make any sense to have
         * callbacks.
         *
         * ```typescript
         * const StringClass = domain.assemblies.mscorlib.image.classes["System.String"];
         * const matches = Il2Cpp.choose<Il2Cpp.String>(StringClass);
         * for (const match of matches) {
         *     console.log(match);
         * }
         * ```
         * @template T Type parameter to automatically cast the objects to other object-like
         * entities, like string and arrays. Default is {@link Il2Cpp.Object | Object}.
         * @param klass The class of the objects you are looking for.
         * @return An array of ready-to-use objects, strings or arrays. Value types are boxed.
         */
        function choose<T extends Object | String | Array<AllowedType> = Object>(klass: Class): T[];

        /**
         * Garbage collector utility functions.
         */
        namespace GC {
            /**
             * Forces the GC to collect object from the given
             * [generation](https://docs.microsoft.com/en-us/dotnet/standard/garbage-collection/fundamentals#generations).
             * @param generation The category of objects to collect.
             */
            function collect(generation: 0 | 1 | 2): void;

            /**
             * Like {@link Il2Cpp.GC.collect | collect}, but I don't know which
             * generation it collects.\
             * Available since Unity version `5.3.5`.
             */
            function collectALittle(): void;

            /**
             * Disables the GC.\
             * Available since Unity version `5.3.5`.
             */
            function disable(): void;

            /**
             * Enables the GC.\
             * Available since Unity version `5.3.5`.
             */
            function enable(): void;

            /**
             * Available since Unity version `2018.3.0`.
             * @return `true` if the GC is disabled, `false` otherwise.
             */
            function isDisabled(): boolean;
        }

        /**
         * Represents a `Il2CppDomain`.
         * ```typescript
         * assert(domain.name == "IL2CPP Root Domain");
         * ```
         */
        class Domain {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * We can iterate over the assemblies using a `for..of` loop,
             * or access a specific assembly using its name, extension omitted.
             * ```typescript
             * for (const assembly of domain.assemblies) {
             * }
             * const mscorlib = assemblies.mscorlib;
             * ```
             * @return Its assemblies.
             */
            get assemblies(): Accessor<Assembly>;

            /**
             * @return Its name. Probably `IL2CPP Root Domain`.
             */
            get name(): string | null;

            /**
             * This is potentially asynchronous because the domain could
             * be initialized at any time, e.g. after `il2cpp_init` is
             * being called.\
             * The domain will already be attached to the caller thread.
             * ```typescript
             * const domain = await Il2Cpp.Domain.get();
             * ```
             * @return The current application domain.
             */
            static get(): Promise<Domain>;
        }

        /**
         * Represents a `Il2CppAssembly`.
         * ```typescript
         * const mscorlibAssembly = domain.assemblies.mscorlib;
         * assert(mscorlibAssembly.name == "mscorlib");
         * ```
         */
        class Assembly {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @return Its image.
             */
            get image(): Image;

            /**
             * @return Its name.
             */
            get name(): string;
        }

        /**
         * Represents a `Il2CppImage`.
         * ```typescript
         * let count = 0;
         * let prev: Il2Cpp.Image | undefined = undefined;
         * for (const assembly of domain.assemblies) {
         *     const current = assembly.image;
         *     if (prev != undefined && prev.classStart != -1) {
         *         assert(current.classStart == count);
         *     }
         *     count += current.classCount;
         *     prev = assembly.image;
         * }
         * //
         * const mscorlib = domain.assemblies.mscorlib.image;
         * assert(mscorlib.name == "mscorlib.dll");
         * ```
         */
        class Image {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @return The count of its classes.
             */
            get classCount(): number;

            /**
             * Non-generic types are stored in sequence.
             * @return The start index of its classes, `-1` if this information
             * is not available - since Unity version `2020.2.0`.
             */
            get classStart(): number | -1;

            /**
             * We can iterate over its classes using a `for..of` loop,
             * or access a specific assembly using its full type name.
             * ```typescript
             * const mscorlib = assemblies.mscorlib.image;
             * for (const klass of mscorlib.classes) {
             * }
             * const BooleanClass = mscorlib.classes["System.Boolean"];
             * ```
             * @return Its classes.
             */
            get classes(): Accessor<Class>;

            /**
             * @return Its name, equals to the name of its assembly plus its
             * extension.
             */
            get name(): string;

            /**
             * @param namespace The class namespace.
             * @param name The class name.
             * @return The class for the given namespace and name or `null` if
             * not found.
             */
            getClassFromName(namespace: string, name: string): Class | null;
        }

        /**
         * Represents a `Il2CppClass`.
         * ```typescript
         * const mscorlib = domain.assemblies.mscorlib.image;
         * //
         * const BooleanClass = mscorlib.classes["System.Boolean"];
         * const Int32Class = mscorlib.classes["System.Int32"];
         * const Int64Class = mscorlib.classes["System.Int64"];
         * const ObjectClass = mscorlib.classes["System.Object"];
         * const StringClass = mscorlib.classes["System.String"];
         * const DateTimeFormatInfoClass = mscorlib.classes["System.Globalization.DateTimeFormatInfo"];
         * const DayOfWeekClass = mscorlib.classes["System.DayOfWeek"];
         * const MathClass = mscorlib.classes["System.Math"];
         * const IFormattableClass = mscorlib.classes["System.IFormattable"];
         * //
         * assert(BooleanClass.arrayClass.name == "Boolean[]");
         * //
         * assert(Int32Class.arrayElementSize == 4);
         * assert(Int64Class.arrayElementSize == 8);
         * assert(ObjectClass.arrayElementSize == Process.pointerSize);
         * //
         * assert(Int32Class.assemblyName == "mscorlib");
         * //
         * const ExecutionContext = mscorlib.classes["System.Threading.ExecutionContext"];
         * const Flags = mscorlib.classes["System.Threading.ExecutionContext.Flags"];
         * assert(ExecutionContext.handle.equals(Flags.declaringClass!.handle));
         * //
         * const dayNames = DateTimeFormatInfoClass.fields.dayNames;
         * assert(dayNames.type.name == "System.String[]");
         * assert(dayNames.type.class.elementClass!.type.name == "System.String");
         * //
         * assert(StringClass.hasStaticConstructor == (".cctor" in StringClass.methods));
         * assert(DateTimeFormatInfoClass.hasStaticConstructor == (".cctor" in DateTimeFormatInfoClass.methods));
         * //
         * assert(Int32Class.image.name == "mscorlib.dll");
         * //
         * assert(DayOfWeekClass.isEnum);
         * assert(!Int32Class.isEnum);
         * //
         * assert(IFormattableClass.isInterface);
         * //
         * if (!MathClass.isStaticConstructorFinished) {
         *     MathClass.ensureInitialized();
         *     assert(MathClass.isStaticConstructorFinished);
         * }
         * //
         * assert(Int32Class.isStruct);
         * assert(!StringClass.isStruct);
         * //
         * assert(BooleanClass.name == "Boolean");
         * //
         * assert(BooleanClass.namespace == "System");
         * //
         * assert(BooleanClass.parent!.type.name == "System.ValueType");
         * assert(ObjectClass.parent == null);
         * //
         * assert(BooleanClass.type.name == "System.Boolean");
         * ```
         */
        class Class {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * The inverse of {@link Il2Cpp.Class.elementClass | elementClass}.
             * @return The array class which has the caller as element class.
             */
            get arrayClass(): Class;

            /**
             * @return The size as array element.
             */
            get arrayElementSize(): number;

            /**
             * @returns The name of the assembly it belongs to.
             */
            get assemblyName(): string;

            /**
             * ```csharp
             * namespace System.Threading
             * {
             *     class ExecutionContext
             *     {
             *         class Flags
             *         {
             *         }
             *     }
             * }
             * ```
             * @return Its outer class if its a nested class, `null` otherwise.
             */
            get declaringClass(): Class | null;

            /**
             * Its element class if it's an array.
             */
            get elementClass(): Class | null;

            /**
             * @return The count of its fields.
             */
            get fieldCount(): number;

            /**
             * We can iterate over the fields a `for..of` loop, or access
             * a specific field using its name.
             * ```typescript
             * const MathClass = mscorlib.classes["System.Math"];
             * for (const fields of MathClass.fields) {
             * }
             * const PI = MathClass.fields.PI;
             * ```
             * @return Its fields.
             */
            get fields(): Accessor<Field>;

            /**
             * @return `true` if it has a static constructor, `false` otherwise.
             */
            get hasStaticConstructor(): boolean;

            /**
             * @return The image it belongs to.
             */
            get image(): Image;

            /**
             * @return The size of its instance.
             */
            get instanceSize(): number;

            /**
             * @return `true` if it's an `enum`, `false` otherwise.
             */
            get isEnum(): boolean;

            /**
             * @return `true` if it's an `interface`, `false` otherwise.
             */
            get isInterface(): boolean;

            /**
             * @return `true` If its static constructor has been already called,
             * so if its static data has been initialized, `false` otherwise.
             */
            get isStaticConstructorFinished(): boolean;

            /**
             * @return `true` if it's a value type (aka struct), `false` otherwise.
             */
            get isStruct(): boolean;

            /**
             * @return The count of its implemented interfaces.
             */
            get interfaceCount(): number;

            /**
             * We can iterate over the interfaces using a `for..of` loop,
             * or access a specific method using its name.
             * ```typescript
             * const StringClass = mscorlib.classes["System.String"];
             * for (const interfaze of StringClass.interfaces) {
             * }
             * const IComparable = StringClass.interfaces["System.IComparable"];
             * ```
             * @return Its interfaces.
             */
            get interfaces(): Accessor<Class>;

            /**
             * @return The count of its methods.
             */
            get methodCount(): number;

            /**
             * We can iterate over the methods using a `for..of` loop,
             * or access a specific method using its name.
             * ```typescript
             * const MathClass = mscorlib.classes["System.Math"];
             * for (const method of MathClass.methods) {
             * }
             * const Log10 = MathClass.methods.Log10;
             * ```
             * @return Its methods.
             */
            get methods(): Accessor<Method>;

            /**
             * @return Its name.
             */
            get name(): string;

            /**
             * @return Its namespace.
             */
            get namespace(): string;

            /**
             * @return Its parent if there is, `null.` otherwise.
             */
            get parent(): Class | null;

            /**
             * @return A pointer to its static fields.
             */
            get staticFieldsData(): NativePointer;

            /**
             * @return Its type.
             */
            get type(): Type;

            /**
             * It makes sure its static data has been initialized.\
             * See {@link isStaticConstructorFinished} for an example.
             */
            ensureInitialized(): void;

            /**
             * It traces all its methods.\
             * See {@link Il2Cpp.Method.trace | trace} for more details.
             */
            trace(): void;
        }

        /**
         * Represents a `Il2CppGenericClass`.
         */
        class GenericClass {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @return Its class.
             */
            get cachedClass(): Class | null;
        }

        /**
         * Represents a `FieldInfo`.
         * ```typescript
         * const mscorlib = domain.assemblies.mscorlib.image;
         * //
         * const BooleanClass = mscorlib.classes["System.Boolean"];
         * const MathClass = mscorlib.classes["System.Math"];
         * const ThreadClass = mscorlib.classes["System.Threading.Thread"];
         * //
         * const CoreModule = domain.assemblies["UnityEngine.CoreModule"].image;
         * const Vector2 = CoreModule.classes["UnityEngine.Vector2"];
         * //
         * assert(MathClass.fields.PI.class.handle.equals(MathClass.handle));
         * //
         * assert(Vector2.fields.x.isInstance);
         * assert(!Vector2.fields.oneVector.isInstance);
         * //
         * assert(MathClass.fields.PI.isLiteral);
         * //
         * assert(ThreadClass.fields.current_thread.isThreadStatic);
         * assert(!ThreadClass.fields.m_Delegate.isThreadStatic);
         * //
         * assert(BooleanClass.fields.TrueLiteral.name == "TrueLiteral");
         * //
         * assert(MathClass.fields.PI.type.name == "System.Double");
         * //
         * const vec = Vector2.fields.oneVector.value as Il2Cpp.ValueType;
         * assert(vec.fields.x.value == 1);
         * assert(vec.fields.y.value == 1);
         * //
         * vec.fields.x.value = 42;
         * assert(vec.fields.x.value == 42);
         * ```
         */
        class Field implements Valuable {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @return The class it belongs to.
             */
            get class(): Class;

            /**
             * @return `true` if it's a instance field, `false` otherwise.
             */
            get isInstance(): boolean;

            /**
             * @return `true` if it's literal field, `false` otherwise.
             */
            get isLiteral(): boolean;

            /**
             * @return `true` if it's a thread  field, `false` otherwise.
             */
            get isThreadStatic(): boolean;

            /**
             * @return Its name.
             */
            get name(): string;

            /**
             * A static field offsets is meant as the offset between it's class
             * {@link Il2Cpp.Class.staticFieldsData | staticFieldsData} and its location.
             * A static field offsets is meant as the offset between it's object
             * {@link Il2Cpp.Object.handle | handle} and its location.
             * @return Its offset.
             */
            get offset(): number;

            /**
             * @return Its type.
             */
            get type(): Type;

            /**
             * @return Its value.
             */
            get value(): AllowedType;

            /**
             * NOTE: Thread static or literal values cannot be altered yet.
             * @param v Its new value.
             */
            set value(v: AllowedType);

            /**
             * @return The actual location of its value.
             */
            get valueHandle(): NativePointer;
        }

        /**
         * Represents a `MethodInfo`.
         * ```typescript
         * const mscorlib = domain.assemblies.mscorlib.image;
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
        class Method implements Invokable {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * ```typescript
             * const MathClass = mscorlib.classes["System.Math"];
             * Interceptor.attach(MathClass.actualPointer, {
             *     // ...
             * });
             * ```
             * @return Its actual pointer in memory.
             */
            get actualPointer(): NativePointer;

            /**
             * @return The class it belongs to.
             */
            get class(): Class;

            /**
             * @return `true` if it's generic, `false` otherwise.
             */
            get isGeneric(): boolean;

            /**
             * @return `true` if it's inflated (a generic with a concrete type parameter),
             * false otherwise.
             */
            get isInflated(): boolean;

            /**
             *  @return `true` if it's an instance method, `false` otherwise.
             */
            get isInstance(): boolean;

            /**
             * @return Its name.
             */
            get name(): string;

            /**
             * @return The count of its parameters.
             */
            get parameterCount(): number;

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
            get parameters(): Accessor<Parameter>;

            /**
             * @return Its static fixed offset, useful for static analysis.
             */
            get relativePointerAsString(): string;

            /**
             * @return Its return type.
             */
            get returnType(): Type;

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
            set implementation(callback: ImplementationCallback | null);

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
            invoke<T extends AllowedType>(...parameters: AllowedType[]): T;

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
            intercept({ onEnter, onLeave }: { onEnter?: OnEnterCallback; onLeave?: OnLeaveCallback }): InvocationListener;

            /**
             * Prints a message when the method is invoked.
             * ```typescript
             * TODO
             * ```
             */
            trace(): void;
        }

        /**
         * Callback of a method implementation.
         */
        type ImplementationCallback =
            /**
             * @param this Frida's `InvocationContext`.
             * @param instance Instance whose method is being intercepted, `null` if the
             * method is static.
             * @param parameters Invocation parameters.
             * @return The value that should be returned - mandatory.
             */
            (this: InvocationContext, instance: Object | null, parameters: Accessor<Valuable>) => AllowedType;

        /**
         * Callback of a method `onEnter` interception.
         */
        type OnEnterCallback =
            /**
             * @param this Frida's `InvocationContext`.
             * @param instance Instance whose method is being intercepted, `null` if the
             * method is static.
             * @param parameters Invocation parameters.
             */
            (this: InvocationContext, instance: Object | null, parameters: Accessor<Valuable>) => void;

        /**
         * Callback of a method `onLeave` interception.
         */
        type OnLeaveCallback =
            /**
             * @param this Frida's `InvocationContext`.
             * @param returnValue The value that should be returned.
             */
            (this: InvocationContext, returnValue: Valuable) => void;

        /**
         * Represents a `ParameterInfo`.
         * ```typescript
         * const mscorlib = domain.assemblies.mscorlib.image;
         * //
         * const MathClass = mscorlib.classes["System.Math"];
         * //
         * assert(MathClass.methods.Sqrt.parameters.d.name == "d");
         * //
         * assert(MathClass.methods.Sqrt.parameters.d.position == 0);
         * //
         * assert(MathClass.methods.Sqrt.parameters.d.type.name == "System.Double");
         * ```
         */
        class Parameter implements Valuable {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @return Its name.
             */
            get name(): string;

            /**
             * @return Its position.
             */
            get position(): number;

            /**
             *  @return Its type.
             */
            get type(): Type;

            /**
             * See {@link Il2Cpp.Method.intercept | here} for examples.
             * @return Its value.
             */
            get value(): AllowedType;

            /**
             * See {@link Il2Cpp.Method.intercept | here} for examples.
             * @param v Its new value.
             */
            set value(v: AllowedType);

            /**
             * @return The actual location of its value.
             */
            get valueHandle(): NativePointer;
        }

        /**
         * Abstraction over the a value type (`struct`).
         * NOTE: you may experience few problems with value types.
         * ```typescript
         * const engine = domain.assemblies["UnityEngine.CoreModule"].image;
         * const Vector2 = engine.classes["UnityEngine.Vector2"];
         * //
         * const vec = Vector2.fields.positiveInfinityVector.value as Il2Cpp.ValueType;
         * //
         * assert(vec.class.type.name == "UnityEngine.Vector2");
         * //
         * assert(vec.fields.x.value == Infinity);
         * assert(vec.fields.y.value == Infinity);
         * ```
         */
        class ValueType {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * NOTE: the class is hardcoded when a new instance is created.\
             * It's not completely reliable.
             * @return Its class.
             */
            get class(): Class;

            /**
             * @return Its fields.
             */
            get fields(): Accessor<Valuable>;

            /**
             * See {@link Il2Cpp.Object.unbox} for an example.
             * @return The boxed value type.
             */
            box(): Object;
        }

        /**
         * Represents a `Object`.
         * ```typescript
         * const mscorlib = domain.assemblies.mscorlib.image;
         * const CoreModule = domain.assemblies["UnityEngine.CoreModule"].image;
         * //
         * const OrdinalComparerClass = mscorlib.classes["System.OrdinalComparer"];
         * const Vector2Class = CoreModule.classes["UnityEngine.Vector2"];
         * //
         * const ordinalComparer = Il2Cpp.Object.from(OrdinalComparerClass);
         * assert(ordinalComparer.class.name == "OrdinalComparer");
         * assert(ordinalComparer.base.class.name == "StringComparer");
         * //
         * const vec = Il2Cpp.Object.from(Vector2Class);
         * vec.methods[".ctor"].invoke(36, 4);
         * const vecUnboxed = vec.unbox();
         * assert(vec.fields.x.value == vecUnboxed.fields.x.value);
         * assert(vec.fields.y.value == vecUnboxed.fields.y.value);
         * const vecBoxed = vecUnboxed.box();
         * assert(vecBoxed.fields.x.value == vecUnboxed.fields.x.value);
         * assert(vecBoxed.fields.y.value == vecUnboxed.fields.y.value);
         * assert(!vecBoxed.handle.equals(vec.handle));
         * ```
         */
        class Object {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @param handle It's `NativePointer`.
             */
            constructor(handle: NativePointer);

            /**
             * @return The same object as an instance of its parent.
             */
            get base(): Object;

            /**
             * @return Its class.
             */
            get class(): Class;

            /**
             * See {@link Il2Cpp.Class.fields} for an example.
             * @return Its fields.
             */
            get fields(): Accessor<Valuable>;

            /**
             * See {@link Il2Cpp.Class.methods} for an example.
             * @return Its methods.
             */
            get methods(): Accessor<Invokable>;

            /**
             * NOTE: the object will be allocated only.
             * @param klass The class of the object to allocate.
             * @return A new object.
             */
            static from(klass: Class): Object;

            /**
             * @return The unboxed value type.
             */
            unbox(): ValueType;
        }

        /**
         * Represents a `Il2CppString`.
         * ```typescript
         * const str = Il2Cpp.String.from("Hello!");
         * //
         * assert(str.content == "Hello!");
         * //
         * str.content = "Bye";
         * assert(str.content == "Bye");
         * //
         * assert(str.length == 3);
         * assert(str.content?.length == 3);
         * //
         * assert(str.object.class.type.name == "System.String");
         * assert(str.object.class.type.typeEnum == Il2Cpp.TypeEnum.STRING);
         * ```
         */
        class String {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @return Its actual content.
             */
            get content(): string | null;

            /**
             * @param v The new content.
             */
            set content(v: string | null);

            /**
             * @return Its length.
             */
            get length(): number;

            /**
             * @return The same string as an object.
             */
            get object(): Object;

            /**
             * @param content The string content.
             * @return A new string.
             */
            static from(content: string): String;
        }

        /**
         * Represents a `Il2CppArraySize`.
         * ```typescript
         * const mscorlib = domain.assemblies.mscorlib.image;
         * //
         * const SingleClass = mscorlib.classes["System.Single"];
         * //
         * const array = Il2Cpp.Array.from<number>(SingleClass, [21.5, 55.3, 31.4, 33]);
         * //
         * assert(array.elementSize == SingleClass.arrayElementSize);
         * //
         * assert(array.length == 4);
         * //
         * assert(array.object.class.type.name == "System.Single[]");
         * //
         * assert(array.elementType.name == "System.Single");
         * //
         * assert(array.object.class.type.typeEnum == Il2Cpp.TypeEnum.SZARRAY);
         * //
         * assert(array.get(0) == 21.5);
         * //
         * array.set(0, 5);
         * assert(array.get(0) == 5);
         * //
         * let str = "";
         * for (const e of array) {
         *     str += Math.ceil(e) + ",";
         * }
         * assert(str == "5,56,32,33,");
         * ```
         */
        class Array<T extends AllowedType> implements Iterable<T> {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @return The size of each element.
             */
            get elementSize(): number;

            /**
             * @return The type of its elements.
             */
            get elementType(): Type;

            /**
             * @return Its length.
             */
            get length(): number;

            /**
             * @return The same array as an object.
             */
            get object(): Object;

            /**
             * @param klass The class of the elements.
             * @param elements The elements.
             * @return A new array.
             */
            static from<T extends AllowedType>(klass: Class, elements: T[]): Array<T>;

            /**
             * @param index The index of the element. It must be between the array bounds.
             * @return The element at the given index.
             */
            get(index: number): T;

            /**
             * @param index The index of the element. It must be between the array bounds.
             * @param v The value of the element.
             */
            set(index: number, v: T): void;

            /**
             * Iterable.
             */
            [Symbol.iterator](): Iterator<T>;
        }

        /**
         * Represents a `Il2CppType`.
         * ```typescript
         * const mscorlib = domain.assemblies.mscorlib.image;
         * //
         * const StringClass = mscorlib.classes["System.String"];
         * const Int32Class = mscorlib.classes["System.Int32"];
         * const ObjectClass = mscorlib.classes["System.Object"];
         * //
         * assert(StringClass.type.class.handle.equals(StringClass.handle));
         * //
         * const array = Il2Cpp.Array.from<number>(Int32Class, [0, 1, 2, 3, 4]);
         * assert(array.object.class.type.name == "System.Int32[]");
         * assert(array.object.class.type.dataType?.name == "System.Int32");
         * //
         * assert(StringClass.type.name == "System.String");
         * //
         * assert(Int32Class.type.typeEnum == Il2Cpp.TypeEnum.I4);
         * assert(ObjectClass.type.typeEnum == Il2Cpp.TypeEnum.OBJECT);
         * ```
         */
        class Type {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * @return Its class.
             */
            get class(): Class;

            /**
             * @return If it's an array, the type of its elements, `null` otherwise.
             */
            get dataType(): Type | null;

            /**
             * @returns If it's a generic type, its generic class, `null` otherwise.
             */
            get genericClass(): GenericClass | null;

            /**
             *  @returns `true` if it's passed by reference, `false` otherwise.
             */
            get isByReference(): boolean;

            /**
             * @returns Its name, namespace included and declaring class excluded. If its class is nested,
             * it corresponds to the class name.
             */
            get name(): string;

            /**
             * @returns Its corresponding type.
             */
            get typeEnum(): TypeEnum;
        }

        /**
         * Represents the enum `Il2CppTypeEnum`.
         */
        enum TypeEnum {
            END = 0x00,
            VOID = 0x01,
            BOOLEAN = 0x02,
            CHAR = 0x03,
            I1 = 0x04,
            U1 = 0x05,
            I2 = 0x06,
            U2 = 0x07,
            I4 = 0x08,
            U4 = 0x09,
            I8 = 0x0a,
            U8 = 0x0b,
            R4 = 0x0c,
            R8 = 0x0d,
            STRING = 0x0e,
            PTR = 0x0f,
            BYREF = 0x10,
            VALUETYPE = 0x11,
            CLASS = 0x12,
            VAR = 0x13,
            ARRAY = 0x14,
            GENERICINST = 0x15,
            TYPEDBYREF = 0x16,
            I = 0x18,
            U = 0x19,
            FNPTR = 0x1b,
            OBJECT = 0x1c,
            SZARRAY = 0x1d,
            MVAR = 0x1e,
            CMOD_REQD = 0x1f,
            CMOD_OPT = 0x20,
            INTERNAL = 0x21,
            MODIFIER = 0x40,
            SENTINEL = 0x41,
            PINNED = 0x45,
            ENUM = 0x55
        }

        /**
         * Represents something which has an accessible value.
         */
        interface Valuable {
            /**
             * The actual location.
             */
            valueHandle: NativePointer;

            /**
             * The actual "pretty" value.
             */
            value: AllowedType;
        }

        /**
         * Represents an invokable method.
         */
        interface Invokable {
            /**
             * See {@link Il2Cpp.Method.invoke}.
             */
            invoke<T extends AllowedType>(...parameters: AllowedType[]): T;
        }

        /**
         * Types this module is familiar with.
         */
        type AllowedType = undefined | boolean | number | Int64 | UInt64 | NativePointer | ValueType | Object | String | Array<AllowedType>;

        /**
         * An iterable class with a string index signature.\
         * Upon key clashes, a suffix `_${number}`is appended to the latest key.
         * ```typescript
         * const accessor = new Accessor<string>();
         * accessor.hello = 0;
         * accessor.hello = 1; // Adding the same key!
         * accessor.hello = 2; // Adding the same key, again!
         * Object.keys(accessor); // hello, hello_1, hello_2
         * ```
         */
        class Accessor<T> implements Iterable<T> {
            /**
             * Iterable.
             */
            [Symbol.iterator](): Iterator<T>;

            /**
             * Index signature.
             */
            [key: string]: T;
        }
    }
}
export {};
