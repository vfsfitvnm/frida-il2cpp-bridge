import "./il2cpp/index";

import { UnityVersion } from "./il2cpp/version";
import { NativeStruct, NonNullNativeStruct } from "./utils/native-struct";

declare global {
    /** */
    namespace Il2Cpp {
        /** The Il2Cpp module. */
        const module: Module;

        /** The Unity version of the current application. */
        const unityVersion: UnityVersion;

        /** */
        function initialize(): Promise<void>;

        /** Performs a dump of the assemblies. */
        function dump(filePath?: string): void;

        /** Represents a `Il2CppArraySize`. */
        class Array<T extends Il2Cpp.AllowedType = Il2Cpp.AllowedType> extends NativeStruct implements Iterable<T> {
            /** Gets the size of the object encompassed by the current array. */
            get elementSize(): number;

            /** Gets the type of the object encompassed by the current array. */
            get elementType(): Il2Cpp.Type;

            /** @internal Gets a pointer to the first element of the current array. */
            get elements(): NativePointer;

            /** Gets the total number of elements in all the dimensions of the current array. */
            get length(): number;

            /** Gets the object behind the current array. */
            get object(): Il2Cpp.Object;

            /** Creates a new array. */
            static from<T extends Il2Cpp.AllowedType>(klass: Il2Cpp.Class, elements: T[]): Il2Cpp.Array<T>;

            /** Gets the element at the specified index of the current array. */
            get(index: number): T;

            /** Sets the element at the specified index of the current array. */
            set(index: number, value: T): void;

            /** Iterable. */
            [Symbol.iterator](): IterableIterator<T>;
        }

        /** Represents a `Il2CppAssembly`. */
        class Assembly extends NonNullNativeStruct {
            /** Gets the image of this assembly. */
            get image(): Il2Cpp.Image;

            /** Gets the name of this assembly. */
            get name(): string;
        }

        /** Represents a `Il2CppClass`. */
        class Class extends NonNullNativeStruct {
            /** Gets the array class which encompass the current class. */
            get arrayClass(): Il2Cpp.Class;

            /** Gets the size of the object encompassed by the current array class. */
            get arrayElementSize(): number;

            /** Gets the name of the assembly in which the current class is defined. */
            get assemblyName(): string;

            /** Gets the class that declares the current nested class. */
            get declaringClass(): Il2Cpp.Class | null;

            /** Gets the class of the object encompassed or referred to by the current array, pointer or reference class. */
            get elementClass(): Il2Cpp.Class | null;

            /** Gets the amount of the fields of the current class. */
            get fieldCount(): number;

            /** Gets the fields of the current class. */
            get fields(): Readonly<Record<string, Il2Cpp.Field>>;

            /** Determines whether the current class has a static constructor. */
            get hasStaticConstructor(): boolean;

            /** Gets the image in which the current class is defined. */
            get image(): Il2Cpp.Image;

            /** Gets the of the instances of the current class. */
            get instanceSize(): number;

            /** Determines whether the current class is an enumeration. */
            get isEnum(): boolean;

            /** Determines whether the current class is an interface. */
            get isInterface(): boolean;

            /** Determines whether the static constructor of the current class has been invoked. */
            get isStaticConstructorFinished(): boolean;

            /** Determines whether the current class is a value type. */
            get isValueType(): boolean;

            /** Gets the amount of the implemented or inherited interfaces by the current class. */
            get interfaceCount(): number;

            /** Gets the interfaces implemented or inherited by the current class. */
            get interfaces(): Readonly<Record<string, Il2Cpp.Class>>;

            /** Gets the amount of the implemented methods by the current class. */
            get methodCount(): number;

            /** Gets the methods implemented by the current class. */
            get methods(): Readonly<Record<string, Il2Cpp.Method>>;

            /** Gets the name of the current class. */
            get name(): string;

            /** Gets the namespace of the current class. */
            get namespace(): string;

            /** Gets the class from which the current class directly inherits. */
            get parent(): Il2Cpp.Class | null;

            /** Gets a pointer to the static fields of the current class. */
            get staticFieldsData(): NativePointer;

            /** Gets the type of the current class. */
            get type(): Il2Cpp.Type;

            /** Determines whether an instance of `other` class can be assigned to a variable of the current type. */
            isAssignableFrom(other: Il2Cpp.Class): boolean;

            /** Determines whether the current class derives from `other` class. */
            isSubclassOf(other: Il2Cpp.Class, checkInterfaces: boolean): boolean;

            /** Calls the static constructor of the current class. */
            initialize(): void;

            toString(): string;
        }

        /** Represents a `Il2CppDomain`. */
        class Domain extends NonNullNativeStruct {
            /** Gets the current application domain. */
            static get reference(): Il2Cpp.Domain;

            /** Gets the name of the current application domain. */
            get name(): string | null;

            /** Gets the assemblies that have been loaded into the execution context of this domain. */
            get assemblies(): Readonly<Record<string, Il2Cpp.Assembly>>;
        }

        /** Represents a `FieldInfo`. */
        class Field extends NonNullNativeStruct {
            /** Gets the class in which this field is defined. */
            get class(): Il2Cpp.Class;

            /** Determines whether this field value is written at compile time. */
            get isLiteral(): boolean;

            /** Determines whether this field is static. */
            get isStatic(): boolean;

            /** Determines whether this field is thread static. */
            get isThreadStatic(): boolean;

            /** Gets the name of this field. */
            get name(): string;

            /**
             * Gets the offset of this field, calculated from its class static fields data if this field is static, or
             * from its object location otherwise.
             */
            get offset(): number;

            /** Gets the type of this field. */
            get type(): Il2Cpp.Type;

            /** Gets the value of this field. */
            get value(): AllowedType;

            /** Sets the value of this field. Thread static or literal values cannot be altered yet. */
            set value(value: AllowedType);

            /** Gets the handle of the value of this field. */
            get valueHandle(): NativePointer;

            /** @internal */
            asHeld(handle: NativePointer): WithValue;
        }

        /** Garbage collector utility functions. */
        class GC {
            /** */
            private constructor();

            /** Returns the heap allocated objects of the specified class. This variant reads GC descriptors. */
            static choose(klass: Il2Cpp.Class): Il2Cpp.Object[];

            /** Forces a garbage collection of the specified generation. */
            static collect(generation: 0 | 1 | 2): void;

            /** Forces a garbage collection. */
            static collectALittle(): void;

            /** Disables the garbage collector. */
            static disable(): void;

            /** Enables the garbage collector. */
            static enable(): void;

            /** Determines whether the garbage collector is disabled. */
            static isDisabled(): boolean;
        }

        /** Represents a GCHandle. */
        class GCHandle {
            /** @internal */
            readonly weakRefId: WeakRefId;

            readonly handle: number;

            /** @internal */
            constructor(handle: number);

            /** Gets the object associated to this handle. */
            get target(): Il2Cpp.Object | null;

            /** Frees this handle. */
            free(): void;
        }

        /** Represents a `Il2CppImage`. */
        class Image extends NonNullNativeStruct {
            /** Gets the amount of classes defined in this image. */
            get classCount(): number;

            /** Gets the index of the first class defined in this image. */
            get classStart(): number;

            /** Gets the classes defined in this image. */
            get classes(): Readonly<Record<string, Il2Cpp.Class>>;

            /** Gets the name of this image. */
            get name(): string;

            /** Gets the class with the specified namespace and name defined in this image. */
            getClassFromName(namespace: string, name: string): Il2Cpp.Class | null;
        }

        /** Represents a `Il2CppMemorySnapshot`. */
        class MemorySnapshot extends NonNullNativeStruct {
            /** @internal */
            readonly weakRefId: WeakRefId;

            /** Captures a memory snapshot. */
            constructor();

            /** Gets the objects tracked by this memory snapshot. */
            get objects(): Il2Cpp.Object[];

            /** Gets the amount of objects tracked in this memory snapshot. */
            get trackedObjectCount(): UInt64;

            /** Gets a pointer to the first object tracked in this memory snapshot. */
            get objectsPointer(): NativePointer;

            /** */
            get metadataSnapshot(): Il2Cpp.MetadataSnapshot;

            /** Frees this memory snapshot. */
            free(): void;
        }

        /** Represents a `Il2CppMetadataSnapshot`. */
        class MetadataSnapshot extends NonNullNativeStruct {
            /** */
            get metadataTypeCount(): number;

            /** */
            get metadataTypes(): Il2Cpp.MetadataType[];
        }

        /** Represents a `Il2CppMetadataType`. */
        class MetadataType extends NonNullNativeStruct {
            /** */
            get assemblyName(): string;

            get baseOrElementTypeIndex(): number;

            /** */
            get class(): Il2Cpp.Class;

            /** */
            get name(): string;
        }

        /** Represents a `MethodInfo`. */
        class Method extends NonNullNativeStruct {
            /** Gets the raw pointer to this method. */
            get pointer(): NativePointer;

            /** Gets the class in which this field is defined. */
            get class(): Il2Cpp.Class;

            /** Determines whether this method is generic. */
            get isGeneric(): boolean;

            /** Determines whether this method is inflated (generic with a concrete type parameter). */
            get isInflated(): boolean;

            /** Determines whether this method is static. */
            get isStatic(): boolean;

            /** Gets the name of this method. */
            get name(): string;

            /** Gets the amount of parameters of this method. */
            get parameterCount(): number;

            /** Gets the parameters of this method. */
            get parameters(): Readonly<Record<string, Il2Cpp.Parameter>>;

            /** Gets the static offset of this method, calculated from Il2Cpp module base. */
            get relativePointerAsString(): string;

            /** Gets the return type of this method. */
            get returnType(): Il2Cpp.Type;

            /** @internal */
            get nativeFunction(): NativeFunction;

            /** Replaces the body of this method. */
            set implementation(block: (this: Il2Cpp.Class | Il2Cpp.Object, ...parameters: any[]) => void | Il2Cpp.AllowedType);

            /** @internal */
            get fridaSignature(): string[];

            /** Invokes this method. */
            invoke<T extends Il2Cpp.AllowedType>(...parameters: Il2Cpp.AllowedType[]): T;

            /** @internal */
            invokeRaw(instance: NativePointer, ...parameters: Il2Cpp.AllowedType[]): Il2Cpp.AllowedType;

            restoreImplementation(): void;

            /** @internal */
            asHeld(holder: NativePointer): Invokable;
        }

        /** Represents a `Il2CppObject`. */
        class Object extends NativeStruct {
            /** Gets the size of the `Il2CppObject` C struct. */
            static get headerSize(): number;

            /** Gets this object casted to its base type. */
            get base(): Il2Cpp.Object;

            /** Gets the class of this object. */
            get class(): Il2Cpp.Class;

            /** Gets the fields of this object. */
            get fields(): Readonly<Record<string, Il2Cpp.WithValue>>;

            /** Gets the methods of this object. */
            get methods(): Readonly<Record<string, Il2Cpp.Invokable>>;

            /** Allocates a new object of the specified class. */
            static from(klass: Il2Cpp.Class): Il2Cpp.Object;

            /** Creates a reference to this object. */
            ref(pin: boolean): Il2Cpp.GCHandle;

            /** Unboxes the value type out of this object. */
            unbox(): Il2Cpp.ValueType;

            /** Creates a weak reference to this object. */
            weakRef(trackResurrection: boolean): Il2Cpp.GCHandle;
        }

        /** Represents a `ParameterInfo`. */
        class Parameter extends NonNullNativeStruct {
            /** Gets the name of this parameter. */
            get name(): string;

            /** Gets the position of this parameter. */
            get position(): number;

            /** Gets the type of this parameter. */
            get type(): Il2Cpp.Type;
        }

        /** Represent a parameter passed by reference. */
        class Reference<T extends Il2Cpp.AllowedType = Il2Cpp.AllowedType> extends NativeStruct {
            readonly type: Il2Cpp.Type;

            constructor(handle: NativePointer, type: Il2Cpp.Type);

            set value(value: T);

            get value(): T;
        }

        /** Represents a `Il2CppString`. */
        class String extends NativeStruct {
            /** Gets the content of this string. */
            get content(): string | null;

            /** Sets the content of this string. */
            set content(value: string | null);

            /** Gets the length of this string. */
            get length(): number;

            /** Gets this string as an object. */
            get object(): Il2Cpp.Object;

            /** Creates a new string with the specified content. */
            static from(content: string): Il2Cpp.String;

            toString(): string | null;
        }

        /** Represents a `Il2CppType`. */
        class Type extends NonNullNativeStruct {
            /** @internal */
            static get offsetOfTypeEnum(): number;

            /** @internal */
            get fridaAlias():
                | "void"
                | "pointer"
                | "bool"
                | "uint32"
                | "uint16"
                | "int32"
                | "uint64"
                | "uint8"
                | "char"
                | "int8"
                | "int16"
                | "int64"
                | "float"
                | "double";

            /** Gets the class of this type. */
            get class(): Il2Cpp.Class;

            /** Gets the encompassed type of this array type. */
            get dataType(): Il2Cpp.Type | null;

            /** Determines whether this type is passed by reference. */
            get isByReference(): boolean;

            /** Gets the name of this type. */
            get name(): string;

            get typeEnum(): Il2Cpp.TypeEnum;
        }

        /** Abstraction over the value type (`struct`). */
        class ValueType extends NativeStruct {
            /** @internal */
            klass: Il2Cpp.Class;

            constructor(handle: NativePointer, klass: Il2Cpp.Class);

            /** Gets the (hardcoded) class of this value type. */
            get class(): Il2Cpp.Class;

            /** Gets the fields of this value type. */
            get fields(): Readonly<Record<string, Il2Cpp.WithValue>>;

            /** Boxed this value type into a object. */
            box(): Il2Cpp.Object;
        }

        /** Dumping utilities. */
        class Dumper {
            /** @internal */
            private constructor();

            static get destinationPath(): string | undefined;

            static dump(generator: () => Generator<string>, destinationPath?: string): void;

            static classicDump(destinationPath?: string): void;

            static snapshotDump(destinationPath?: string): void;
        }

        /** Filtering utilities. */
        class Filtering {
            /** @internal */
            private constructor();

            /** Creates a filter which includes `element`s whose type can be assigned to `klass` variables. */
            static Is<T extends Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type>(klass: Il2Cpp.Class): (element: T) => boolean;

            /** Creates a filter which includes `element`s whose type corresponds to `klass` type. */
            static IsExactly<T extends Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type>(klass: Il2Cpp.Class): (element: T) => boolean;
        }

        /** Tracing utilities. */
        class Tracer {
            /** @internal */
            counter: number;

            /** @internal */
            readonly invocationListeners: InvocationListener[];

            /** @internal */
            readonly logging: Il2Cpp.Tracer.Logging;

            /** @internal */
            constructor(logger: Il2Cpp.Tracer.Logging, ...targets: (Il2Cpp.Class | Il2Cpp.Method)[]);

            /** Creates a tracer with a custom behaviour. */
            static Custom(logger: Il2Cpp.Tracer.Logging, ...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer;

            /** Creates a tracer of onEnter invocations. */
            static Simple(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer;

            /** Creates a tracer of onEnter and onLeave invocations. */
            static Full(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer;

            /** Creates a tracer of onEnter and onLeave invocations, including parameters and return values. */
            // static FullWithValues(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer;

            /** Starts tracing the given targets. */
            add(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): void;

            /** Stops tracing. */
            clear(): void;
        }

        /** Tracing utilities. */
        class Tracer2 {
            /** @internal */
            counter: number;

            /** @internal */
            readonly methods: Il2Cpp.Method[];

            /** @internal */
            // readonly logging: Il2Cpp.Tracer2.Logging;

            /** @internal */
            constructor(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]);

            /** Creates a tracer with a custom behaviour. */
            // static Custom(logger: Il2Cpp.Tracer.Logging, ...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer;

            /** Creates a tracer of onEnter invocations. */
            // static Simple(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer;

            /** Creates a tracer of onEnter and onLeave invocations. */
            // static Full(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer;

            /** Creates a tracer of onEnter and onLeave invocations, including parameters and return values. */
            static FullWithValues(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): Il2Cpp.Tracer2;

            /** Starts tracing the given targets. */
            // add(...targets: (Il2Cpp.Class | Il2Cpp.Method)[]): void;

            /** Stops tracing. */
            clear(): void;
        }

        /** */
        namespace Tracer {
            /** */
            type Logging = (this: Il2Cpp.Tracer, method: Il2Cpp.Method) => InvocationListenerCallbacks;
        }

        /** */
        namespace Tracer2 {
            /** */
            type Logging = (this: Il2Cpp.Tracer2, method: Il2Cpp.Method) => void;
        }

        /** Represents an invokable method. */
        interface Invokable {
            invoke<T extends Il2Cpp.AllowedType>(...parameters: Il2Cpp.AllowedType[]): T;
        }

        /** Represents something which has an accessible value. */
        interface WithValue {
            /** The actual "pretty" value. */
            value: Il2Cpp.AllowedType;

            /** The actual location. */
            valueHandle: NativePointer;
        }

        /** Represents a `Il2CppTypeEnum`. */
        type TypeEnum =
            | "end"
            | "void"
            | "boolean"
            | "char"
            | "i1"
            | "u1"
            | "i2"
            | "u2"
            | "i4"
            | "u4"
            | "i8"
            | "u8"
            | "r4"
            | "r8"
            | "string"
            | "ptr"
            | "byref"
            | "valuetype"
            | "class"
            | "var"
            | "array"
            | "genericinst"
            | "typedbyref"
            | "i"
            | "u"
            | "fnptr"
            | "object"
            | "szarray"
            | "mvar"
            | "cmod_reqd"
            | "cmod_opt"
            | "internal"
            | "modifier"
            | "sentinel"
            | "pinned"
            | "enum";

        /** Types this module is familiar with. */
        type AllowedType =
            | boolean
            | number
            | Int64
            | UInt64
            | NativePointer
            | Il2Cpp.ValueType
            | Il2Cpp.Object
            | Il2Cpp.String
            | Il2Cpp.Array
            | Il2Cpp.Reference;
    }

    /** @internal */
    namespace console {
        function log(message?: any, ...optionalParams: any[]): void;
    }
}
