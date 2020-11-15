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
         * the IL2CPP library could be loaded at any
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
         * TODO
         */
        function dump(): Promise<void>;

        /**
         * Represents a `Il2CppDomain`.
         */
        class Domain {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * Its assemblies.\
             * We can iterate over them using a `for..of` loop, or access a
             * specific assembly using its name, extension omitted.
             * ```typescript
             * for (const assembly of domain.assemblies) {
             * }
             * const CSharpAssembly = assemblies.Assembly_CSharp;
             * ```
             */
            get assemblies(): Accessor<Assembly>;

            /**
             * Its name. Probably `IL2CPP Root Domain`.
             */
            get name(): string | null;

            /**
             * This is how we obtain the domain. This is potentially asynchronous
             * because the domain could be initialized at any time, e.g.
             * after `il2cpp_init` is being called.\
             * The domain will already be attached to the calling thread,
             * in order to avoid access violation errors.
             * ```typescript
             * const domain = await Il2Cpp.Domain.get();
             * ```
             */
            static get(): Promise<Domain>;
        }

        /**
         * Represents a `Il2CppAssembly`.
         */
        class Assembly {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * Its image, which contains the information
             * about the assembly.
             * ```typescript
             * const CSharp = assemblies.Assembly_CSharp.image;
             * ```
             */
            get image(): Image;

            /**
             * Its name, e.g.`Assembly-CSharp`.
             */
            get name(): string;
        }

        /**
         * Represents a `Il2CppImage`.
         */
        class Image {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * The amount of classes inside the image.
             */
            get classCount(): number;

            /**
             * Non-generic types are stored in sequence.
             * ```typescript
             * assert(Image0.classStart == 0 && Image0.classCount == x);
             * assert(Image1.classStart == x + 1 && Image1.classCount == y);
             * assert(Image2.classStart == y + 1 && Image2.classCount == z);
             * // And so on
             * ```
             */
            get classStart(): number | -1;

            /**
             * Its classes.\
             * We can iterate over them using a `for..of` loop, or access
             * a specific assembly using its full type name.
             * ```typescript
             * const CSharp = assemblies.Assembly_CSharp.image;
             * for (const klass of CSharp.classes) {
             * }
             * const MyClass = CSharp.classes.Namespace_MyClass;
             * ```
             */
            get classes(): Accessor<Class>;

            /**
             * Its name, equals to the name of its assembly plus its
             * extension,e.g. `Assembly-CSharp.dll`.
             */
            get name(): string;
        }

        /**
         * Represents a `Class`.
         */
        class Class {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * The size as array element, e.g. `Process.pointerSize` if
             * the class is an object, or less if it's a value type.
             */
            get arrayElementSize(): number;

            /**
             * The name of the assembly it belongs to.
             */
            get assemblyName(): string;

            /**
             * Its outer class if its a nested class.
             * ```csharp
             * class Outer
             * {
             *    class Inner
             *    {
             *    }
             * }
             * ```
             * e.g:
             * ```typescript
             * const Outer = CSharp.classes.Example_Outer;
             * const Inner = CSharp.classes.Inner;
             * assert(Outer.handle.equals(Inner.declaringClass.handle));
             * ```
             */
            get declaringClass(): Class | null;

            /**
             * Its element class if it's an array.
             * ```typescript
             * const StringArray = ...;
             * assert(StringArray.type.name == "System.String[]");
             * assert(StringArray.elementClass.type.name == "System.String");
             * ```
             */
            get elementClass(): Class | null;

            /**
             * The count of its fields.
             */
            get fieldCount(): number;

            /**
             * Its fields.\
             * We can iterate over them using a `for..of` loop, or access
             * a specific field using its name.
             * ```typescript
             * const MyClass = CSharp.classes.Namespace_MyClass;
             * for (const fields of MyClass.fields) {
             * }
             * const myField = MyClass.fields.myField;
             * ```
             */
            get fields(): Accessor<Field>;

            /**
             * If the class has a static constructor.
             */
            get hasStaticConstructor(): boolean;

            /**
             * The image it belongs to.
             */
            get image(): Image;

            /**
             * The size of its instance.
             */
            get instanceSize(): number;

            /**
             * If it's an enum.
             */
            get isEnum(): boolean;

            /**
             * If its static constructor has been already called,
             * so if its static data has been initialized.
             */
            get isStaticConstructorFinished(): boolean;

            /**
             * If it's a value type (aka struct).
             * ```typescript
             * const BooleanClass = mscorlib.classes.System_Boolean;
             * assert(BooleanClass.isStruct == true);
             * const StringClass = mscorlib.classes.System_String;
             * assert(StringClass.isStruct == false);
             * ```
             */
            get isStruct(): boolean;

            /**
             * The count of its methods.
             */
            get methodCount(): number;

            /**
             * Its callable or manipulable static methods.\
             * We can iterate over them using a `for..of` loop, or access
             * a specific method using its name.
             * ```typescript
             * const MyClass = CSharp.classes.Namespace_MyClass;
             * for (const method of MyClass.methods) {
             * }
             * const myMethod = MyClass.methods.myMethod;
             * ```
             */
            get methods(): Accessor<Method>;

            /**
             * Its name.
             * ```typescript
             * const BooleanClass = mscorlib.classes.System_Boolean;
             * assert(BooleanClass.name == "Boolean");
             * ```
             */
            get name(): string;

            /**
             * Its namespace.
             * ```typescript
             * const BooleanClass = mscorlib.classes.System_Boolean;
             * assert(BooleanClass.namespace == "System");
             * ```
             */
            get namespace(): string;

            /**
             * Its parent.
             * ```typescript
             * const BooleanClass = mscorlib.classes.System_Boolean;
             * assert(BooleanClass.parent.type.name == "System.ValueType");
             * ```
             */
            get parent(): Class | null;

            /**
             * A pointer to its static fields.
             */
            get staticFieldsData(): NativePointer;

            /**
             * Its type.
             * ```typescript
             * const BooleanClass = mscorlib.classes.System_Boolean;
             * assert(BooleanClass.type.name == "System.Boolean");
             * ```
             */
            get type(): Type;

            /**
             * It makes sure its static data has been initialized.
             * ```typescript
             * const BooleanClass = mscorlib.classes.System_Boolean;
             * BooleanClass.ensureInitialized();
             * const TrueLiteral = BooleanClass.fields.TrueLiteral.value as Il2Cpp.String;
             * assert(TrueLiteral.content == "True");
             * ```
             */
            ensureInitialized(): void;

            /**
             * It traces all its methods.\
             * See {@link Il2Cpp.Method.trace} for more details.
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

            get cachedClass(): Class | null;
        }

        /**
         * Represents a `FieldInfo`.
         */
        class Field implements Valuable {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * The class it belongs to.
             * ```typescript
             * const MathClass = mscorlib.classes.System_Math;
             * const PI = MathClass.fields.PI;
             * assert(PI.class.handle.equals(MathClass.handle));
             * ```
             */
            get class(): Class;

            /**
             * If it's a instance field.
             */
            get isInstance(): boolean;

            /**
             * If it's literal, aka known at compilation time.
             * ```typescript
             * const MathClass = mscorlib.classes.System_Math;
             * assert(MathClass.fields.PI.isLiteral == true);
             * ```
             */
            get isLiteral(): boolean;

            /**
             * If it's thread static, aka each thread has a
             * different value for it.
             */
            get isThreadStatic(): boolean;

            /**
             * Its name.
             * ```typescript
             * const BooleanClass = mscorlib.classes.System_Boolean;
             * const TrueLiteral = BooleanClass.fields.TrueLiteral;
             * assert(TrueLiteral.name == "TrueLiteral");
             * ```
             */
            get name(): string;

            /**
             * Its offset from {@link Il2Cpp.Class.staticFieldsData | staticFieldsData}
             * if it's static, from a {@link Il2Cpp.Object.handle | handle} otherwise.
             */
            get offset(): number;

            /**
             * Its type.
             * ```typescript
             * const MathClass = mscorlib.classes.System_Math;
             * assert(MathClass.fields.PI.type.name == "System.Double");
             * ```
             */
            get type(): Type;

            get value(): AllowedType;

            set value(v: AllowedType);
        }

        /**
         * Represents a `MethodInfo`.
         */
        class Method {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * Its actual pointer in memory.
             */
            get actualPointer(): NativePointer;

            /**
             * The class it belongs to.
             * ```typescript
             * const MathClass = mscorlib.classes.System_Math;
             * const Sqrt = MathClass.methods.Sqrt;
             * assert(Sqrt.class.handle.equals(MathClass.handle));
             * ```
             */
            get class(): Class;

            /**
             * If it's generic.
             */
            get isGeneric(): boolean;

            /**
             * If it's inflated, aka a generic with
             * a concrete type parameter.
             */
            get isInflated(): boolean;

            /**
             * If it's an instance method.
             */
            get isInstance(): boolean;

            /**
             * Its name.
             * ```typescript
             * const MathClass = mscorlib.classes.System_Math;
             * assert(MathClass.methods.Sqrt.name == "Sqrt");
             * ```
             */
            get name(): string;

            /**
             * The count of its parameters.
             */
            get parameterCount(): number;

            /**
             * Its parameters.\
             * We can iterate over them using a `for..of` loop, or access
             * a specific parameter using its name.
             * ```typescript
             * const CSharp = assemblies.Assembly_CSharp.image;
             * const MyMethod = CSharp.classes.MyClass.methods.MyMethod;
             * for (const parameter of MyMethod.parameters) {
             * }
             * const myParameter = MyMethod.myParameter;
             * ```
             */
            get parameters(): Accessor<Parameter>;

            /**
             * Its static fixed offset, useful for static analysis.
             */
            get relativePointerAsString(): string;

            /**
             * Its return type.
             * const Int32Class = mscorlib.classes.System_Int32;
             * const TupleClass = mscorlib.classes.System_Tuple;
             * const returnType = TupleClass.methods.CombineHashCodes.returnType;
             * assert(returnType.class.handle.equals(Int32Class.handle));
             */
            get returnType(): Type;

            set implementation(callback: ImplementationCallback | null);

            /**
             * Invokes the static method using the supplied parameters.
             * ```typescript
             * const UnityEngine_CoreModule = domain.assemblies.UnityEngine_CoreModule_dll.image;
             * const ApplicationClass = UnityEngine_CoreModule.classes.UnityEngine_Application;
             * const get_identifier = ApplicationClass.methods.get_identifier;
             * get_identifier.invoke(); // com.example.application
             * ```
             */
            /**
             * Invokes as static.
             */
            invoke<T extends AllowedType>(...parameters: AllowedType[]): T;

            /**
             * Shorthand for {@link Il2Cpp.Method.intercept | intercept}.
             * ```typescript
             * const MyMethod = MyClass.methods.MyMethod;
             * MyMethod.onLeave = returnValue => {
             *     const myObject = returnValue.value as Il2Cpp.Object;
             *     assert(myObject.class.type.name == MyMethod.returnType.name);
             * }
             * ```
             * Alternatively, if you need the `InvocationContext`:
             * ```typescript
             * const MyMethod = MyClass.methods.MyMethod;
             * MyMethod.onLeave = function(returnValue) {
             *     const context = this.context as Arm64CpuContext;
             *     assert(context.x0.equals(returnValue.handle));
             * }
             * ```
             */
            /**
             * Shorthand for {@link Il2Cpp.Method.intercept | intercept}.
             * ```typescript
             * const MyMethod = MyClass.methods.MyMethod;
             * MyMethod.onEnter = (instance, parameters) => {
             *     if (MyMethod.isInstance) {
             *         assert(instance.class.handle.equals(MyClass.handle));
             *     } else {
             *         assert(instance.handle.isNull());
             *     }
             * }
             * ```
             * Alternatively, if you need the `InvocationContext`:
             * ```typescript
             * const MyMethod = MyClass.methods.MyMethod;
             * MyMethod.onEnter = function(instance, parameters) {
             *     const context = this.context as Arm64CpuContext;
             *     assert(context.x0.equals(instance.handle));
             *     assert(context.x1.equals(parameters.firstParam.handle));
             *     assert(context.x2.equals(parameters.secondParam.handle));
             * }
             * ```
             */
            intercept({onEnter, onLeave}: {
                onEnter?: OnEnterCallback;
                onLeave?: OnLeaveCallback;
            }): InvocationListener;

            trace(): void;
        }

        /**
         * Represents a `ParameterInfo`.
         */
        class Parameter implements Valuable {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            /**
             * Its name.
             * ```typescript
             * const MathClass = mscorlib.classes.System_Math;
             * assert(MathClass.methods.Sqrt.parameters.d.name == "d");
             * ```
             */
            get name(): string;

            /**
             * Its type.
             * ```typescript
             * const MathClass = mscorlib.classes.System_Math;
             * assert(MathClass.methods.Sqrt.parameters.d.type.name == "System.Double");
             * ```
             */
            get type(): Type;

            get value(): AllowedType;

            set value(v: AllowedType);
        }

        /**
         * Abstraction over the a value type / struct.
         */
        class ValueType {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            readonly klass: Class;

            get fields(): Accessor<Field>;
        }

        /**
         * Represents a `Object`.
         */
        class Object {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            static get headerSize(): number;

            get base(): Object;

            get class(): Class;

            get fields(): Accessor<Field>;

            get methods(): Accessor<Method>;

            static from(klass: Class): Object;
        }

        /**
         * Represents a `Il2CppString`.
         */
        class String {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            get content(): string | null;

            set content(value: string | null);

            get length(): number;

            get object(): Object;

            static from(content: string): String;
        }

        /**
         * Represents a `Il2CppArraySize`.
         */
        class Array<T extends AllowedType> implements Iterable<T> {

            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            get elementSize(): number;

            get length(): number;

            get object(): Object;

            get type(): Type;

            static from<T extends AllowedType>(klass: Class, elements: T[]): Array<T>;

            get(index: number): T;

            set(index: number, v: T): void;

            [Symbol.iterator](): Iterator<T>;
        }

        /**
         * Represents a `Il2CppType`.
         */
        class Type {
            /**
             * Its handle as a `NativePointer`.
             */
            readonly handle: NativePointer;

            get class(): Class;

            get dataType(): Type | null;

            get genericClass(): GenericClass | null;

            get isByReference(): boolean;

            get name(): string;

            get typeEnum(): TypeEnum;
        }

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
            ENUM = 0x55,
        }

        interface Valuable {
            value: AllowedType;
        }

        /**
         * Types you can be familiar with.
         */
        type AllowedType =
            undefined
            | boolean
            | number
            | Int64
            | UInt64
            | NativePointer
            | ValueType
            | Object
            | String
            | Array<AllowedType>;

        type ImplementationCallback = (
            this: InvocationContext,
            instance: Object,
            parameters: Accessor<Parameter>
        ) => AllowedType;

        type OnEnterCallback = (
            this: InvocationContext,
            instance: Object,
            parameters: Accessor<Parameter>
        ) => void;

        type OnLeaveCallback = (this: InvocationContext, returnValue: Valuable) => void;

        /**
         * An iterable class with a string index signature.\
         * Upon key clashes, a suffix `_${number}`is appended to the latest key.
         * ```typescript
         * const accessor = new Accessor<string>();
         * // Let's add something
         * accessor.hello = 0;
         * accessor.hello = 1; // Adding the same key!
         * accessor.hello = 2; // Adding the same key, again!
         * // Result
         * Object.keys(accessor); // hello, hello_1, hello_2
         * ```
         */
        class Accessor<T> implements Iterable<T> {

            [Symbol.iterator](): Iterator<T>;

            [key: string]: T;
        }
    }
}
export {};
