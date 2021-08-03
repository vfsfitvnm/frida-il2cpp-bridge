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

        /** Represents a `Il2CppArraySize`. */
        class Array<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends NativeStruct implements Iterable<T> {
            /** Creates a new array. */
            static from<T extends Il2Cpp.Field.Type>(klass: Il2Cpp.Class, elements: T[]): Il2Cpp.Array<T>;

            /** Gets the size of the object encompassed by the current array. */
            get elementSize(): number;

            /** Gets the type of the object encompassed by the current array. */
            get elementType(): Il2Cpp.Type;

            /** @internal Gets a pointer to the first element of the current array. */
            get elements(): Il2Cpp.Pointer<T>;

            /** Gets the total number of elements in all the dimensions of the current array. */
            get length(): number;

            /** Gets the object behind the current array. */
            get object(): Il2Cpp.Object;

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

            /** Determines whether the current class has a class constructor. */
            get hasClassConstructor(): boolean;

            /** Gets the image in which the current class is defined. */
            get image(): Il2Cpp.Image;

            /** Gets the size of the instances of the current class. */
            get instanceSize(): number;

            /** Determines whether the current class is an enumeration. */
            get isEnum(): boolean;

            /** */
            get isGeneric(): boolean;

            /** */
            get isInflated(): boolean;

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

            /** Calls the static constructor of the current class. */
            initialize(): void;

            /** Determines whether an instance of `other` class can be assigned to a variable of the current type. */
            isAssignableFrom(other: Il2Cpp.Class): boolean;

            /** Determines whether the current class derives from `other` class. */
            isSubclassOf(other: Il2Cpp.Class, checkInterfaces: boolean): boolean;
        }

        /** Represents a `Il2CppDomain`. */
        class Domain extends NativeStruct {
            /** Gets the current application domain. */
            static get reference(): Il2Cpp.Domain;

            /** Gets the assemblies that have been loaded into the execution context of this domain. */
            get assemblies(): Readonly<Record<string, Il2Cpp.Assembly>>;

            /** Gets the name of the current application domain. */
            get name(): string;

            /** */
            open(assemblyName: string): Il2Cpp.Assembly | null;
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
            get value(): Il2Cpp.Field.Type;

            /** Sets the value of this field. Thread static or literal values cannot be altered yet. */
            set value(value: Il2Cpp.Field.Type);

            /** @internal */
            get valueHandle(): NativePointer;

            /** @internal */
            withHolder(instance: Il2Cpp.Object | Il2Cpp.ValueType): Il2Cpp.Field;
        }

        /** */
        namespace Field {
            /** */
            type Type =
                | boolean
                | number
                | Int64
                | UInt64
                | NativePointer
                | Il2Cpp.Pointer
                | Il2Cpp.ValueType
                | Il2Cpp.Object
                | Il2Cpp.String
                | Il2Cpp.Array;
        }

        /** Garbage collector utility functions. */
        class GC {
            /** */
            private constructor();

            /** Gets the heap size in bytes. */
            static get heapSize(): Int64;

            /** Gets the used heap size in bytes. */
            static get usedHeapSize(): Int64;

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
            /** */
            readonly handle: number;

            /** @internal */
            readonly weakRefId: WeakRefId;

            /** @internal */
            constructor(handle: number);

            /** Gets the object associated to this handle. */
            get target(): Il2Cpp.Object | null;

            /** Frees this handle. */
            free(): void;
        }

        /** */
        class GenericClass extends NonNullNativeStruct {
            /** */
            get cachedClass(): Il2Cpp.Class;

            /** */
            get classGenericInstance(): Il2Cpp.GenericInstance | null;

            /** */
            get methodGenericInstance(): Il2Cpp.GenericInstance | null;
        }

        /** */
        class GenericInstance extends NonNullNativeStruct {
            /** */
            get typesCount(): number;

            /** */
            get types(): Readonly<Record<string, Il2Cpp.Type>>;
        }

        /** Represents a `Il2CppImage`. */
        class Image extends NonNullNativeStruct {
            /** */
            static get corlib(): Il2Cpp.Image;

            /** */
            get assembly(): Il2Cpp.Assembly;

            /** Gets the amount of classes defined in this image. */
            get classCount(): number;

            /** Gets the classes defined in this image. */
            get classes(): Readonly<Record<string, Il2Cpp.Class>>;

            /** Gets the index of the first class defined in this image. */
            get classStart(): number;

            /** Gets the name of this image. */
            get name(): string;

            /** Gets the class with the specified namespace and name defined in this image. */
            getClassFromName(namespace: string, name: string): Il2Cpp.Class | null;
        }

        /** Represents a `Il2CppMemorySnapshot`. */
        class MemorySnapshot extends NonNullNativeStruct {
            /** Captures a memory snapshot. */
            static capture(): Il2Cpp.MemorySnapshot;

            /** */
            get metadataSnapshot(): Il2Cpp.MetadataSnapshot;

            /** Gets the objects tracked by this memory snapshot. */
            get objects(): Il2Cpp.Object[];

            /** Gets a pointer to the first object tracked in this memory snapshot. */
            get objectsPointer(): NativePointer;

            /** Gets the amount of objects tracked in this memory snapshot. */
            get trackedObjectCount(): UInt64;

            /** Frees this memory snapshot. */
            free(): void;
        }

        /** Represents a `Il2CppMetadataSnapshot`. */
        class MetadataSnapshot extends NonNullNativeStruct {
            /** */
            get metadataTypeCount(): number;

            /** */
            get metadataTypes(): Readonly<Record<string, Il2Cpp.MetadataType>>;
            // get metadataTypes(): Il2Cpp.MetadataType[];
        }

        /** Represents a `Il2CppMetadataType`. */
        class MetadataType extends NonNullNativeStruct {
            /** */
            get assemblyName(): string;

            /** */
            get baseOrElementTypeIndex(): number;

            /** */
            get class(): Il2Cpp.Class;

            /** */
            get name(): string;
        }

        /** Represents a `MethodInfo`. */
        class Method extends NonNullNativeStruct {
            /** Gets the class in which this field is defined. */
            get class(): Il2Cpp.Class;

            get fridaSignature(): NativeCallbackArgumentType[];

            /** Determines whether this method is generic. */
            get isGeneric(): boolean;

            /** Determines whether this method is inflated (generic with a concrete type parameter). */
            get isInflated(): boolean;

            /** Determines whether this method is static. */
            get isStatic(): boolean;

            /** Gets the name of this method. */
            get name(): string;

            /** @internal */
            get nativeFunction(): NativeFunction<any, any>;

            /** */
            get object(): Il2Cpp.Object;

            /** Gets the amount of parameters of this method. */
            get parameterCount(): number;

            /** Gets the parameters of this method. */
            get parameters(): Readonly<Record<string, Il2Cpp.Parameter>>;

            /** Gets the relative virtual address (RVA) of this method. */
            get relativeVirtualAddress(): NativePointer;

            /** Gets the return type of this method. */
            get returnType(): Il2Cpp.Type;

            /** Gets the virtual address (VA) to this method. */
            get virtualAddress(): NativePointer;

            /** Replaces the body of this method. */
            set implementation(block: Il2Cpp.Method.Implementation);

            /** Invokes this method. */
            invoke<T extends Il2Cpp.Method.ReturnType>(...parameters: Il2Cpp.Parameter.Type[]): T;

            /** @internal */
            invokeRaw(instance: NativePointer, ...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Method.ReturnType;

            /** */
            restoreImplementation(): void;

            /** @internal */
            withHolder(instance: Il2Cpp.Object): Il2Cpp.Method;
        }

        /** */
        namespace Method {
            /** */
            type Implementation = (this: Il2Cpp.Class | Il2Cpp.Object, ...parameters: any[]) => Il2Cpp.Method.ReturnType;

            /** */
            type ReturnType = void | Il2Cpp.Field.Type;
        }

        /** Represents a `Il2CppObject`. */
        class Object extends NativeStruct {
            /** Gets the size of the `Il2CppObject` C struct. */
            static get headerSize(): number;

            /** Allocates a new object of the specified class. */
            static from(klass: Il2Cpp.Class): Il2Cpp.Object;

            /** Gets this object casted to its base type. */
            get base(): Il2Cpp.Object;

            /** Gets the class of this object. */
            get class(): Il2Cpp.Class;

            /** Gets the fields of this object. */
            get fields(): Readonly<Record<string, Il2Cpp.Field>>;

            /** Gets the methods of this object. */
            get methods(): Readonly<Record<string, Il2Cpp.Method>>;

            /** Creates a reference to this object. */
            ref(pin: boolean): Il2Cpp.GCHandle;

            /** Unboxes the value type out of this object. */
            unbox(): NativePointer;

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

        /** */
        namespace Parameter {
            /** */
            type Type = Il2Cpp.Field.Type | Il2Cpp.Reference;
        }

        /** */
        class Pointer<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends NativeStruct implements Iterable<T> {
            /** */
            readonly type: Il2Cpp.Type;

            /** @internal */
            constructor(handle: NativePointer, type: Il2Cpp.Type);

            /** */
            get values(): T[];

            /** */
            set values(values: T[]);

            /** */
            get(index: number): T;

            /** */
            getElementHandle(index: number): NativePointer;

            /** */
            read(offset?: number, length?: number): T[];

            /** */
            set(index: number, value: T): void;

            /** */
            write(values: T[], offset?: number): void;

            /** Iterable. */
            [Symbol.iterator](): IterableIterator<T>;
        }

        /** Represent a parameter passed by reference. */
        class Reference<T extends Il2Cpp.Field.Type = Il2Cpp.Field.Type> extends NativeStruct {
            /** */
            readonly type: Il2Cpp.Type;

            /** @internal */
            constructor(handle: NativePointer, type: Il2Cpp.Type);

            /** */
            get value(): T;

            /** */
            set value(value: T);
        }

        /** Represents a `Il2CppString`. */
        class String extends NativeStruct {
            /** Creates a new string with the specified content. */
            static from(content: string): Il2Cpp.String;

            /** Gets the content of this string. */
            get content(): string | null;

            /** Gets the length of this string. */
            get length(): number;

            /** Gets this string as an object. */
            get object(): Il2Cpp.Object;

            /** Sets the content of this string. */
            set content(value: string | null);
        }

        class ValueType extends NativeStruct {
            readonly type: Il2Cpp.Type;

            constructor(handle: NativePointer, type: Il2Cpp.Type);

            get fields(): Readonly<Record<string, Il2Cpp.Field>>;

            box(): Il2Cpp.Object;
        }

        /** Represents a `Il2CppType`. */
        class Type extends NonNullNativeStruct {
            /** @internal */
            static get offsetOfTypeEnum(): number;

            /** Gets the class of this type. */
            get class(): Il2Cpp.Class;

            /** Gets the encompassed type of this array type. */
            get dataType(): Il2Cpp.Type | null;

            /** */
            get fridaAlias(): NativeCallbackArgumentType;

            /** */
            get genericClass(): Il2Cpp.GenericClass;

            /** Determines whether this type is passed by reference. */
            get isByReference(): boolean;

            /** Gets the name of this type. */
            get name(): string;

            /** */
            get object(): Il2Cpp.Object;

            /** */
            get typeEnum(): Il2Cpp.Type.Enum;
        }

        /** */
        namespace Type {
            /** Represents a `Il2CppTypeEnum`. */
            type Enum =
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
        }

        /** Dumping utilities. */
        class Dumper {
            /** @internal */
            private constructor();

            /** */
            static get directoryPath(): string;

            /** */
            static get fileName(): string;

            /** */
            static classicDump(fileName?: string, destinationDirectoryPath?: string): void;

            /** */
            static dump(generator: () => Generator<string>, fileName?: string, destinationDirectoryPath?: string): void;

            /** */
            static snapshotDump(fileName?: string, destinationDirectoryPath?: string): void;
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
            private constructor();

            /** Reports method invocations, input arguments, returns and return values. */
            static fullWithValuesTrace(...targets: Il2Cpp.Tracer.Targets): void;

            /** Reports method invocations and returns. */
            static fullTrace(...targets: Il2Cpp.Tracer.Targets): void;

            /** Reports method invocations. */
            static simpleTrace(...targets: Il2Cpp.Tracer.Targets): void;

            /** Traces the given methods. */
            static trace(callbacksGenerator: (method: Il2Cpp.Method) => Il2Cpp.Tracer.Callbacks, ...targets: Il2Cpp.Tracer.Targets): void;
        }

        /** */
        namespace Tracer {
            /** */
            type Callbacks = RequireAtLeastOne<{
                onEnter?: (...parameters: Il2Cpp.Parameter.Type[]) => void;
                onLeave?: (returnValue: Il2Cpp.Method.ReturnType) => void;
            }>;

            /** */
            type Targets = (Il2Cpp.Method | Il2Cpp.Class)[];
        }
    }

    /** https://docs.microsoft.com/en-us/javascript/api/@azure/keyvault-certificates/requireatleastone */
    type RequireAtLeastOne<T> = { [K in keyof T]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<keyof T, K>>> }[keyof T];

    /** @internal */
    namespace console {
        function log(message?: any, ...optionalParams: any[]): void;
    }
}
