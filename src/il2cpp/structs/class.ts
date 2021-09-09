import { cache } from "decorator-cache-getter";

import { isEqualOrAbove } from "../decorators";

import { NonNullNativeStruct } from "../../utils/native-struct";
import { addLevenshtein, getOrNull, makeIterable, preventKeyClash } from "../../utils/utils";
import { raise } from "../../utils/console";

/** Represents a `Il2CppClass`. */
class Il2CppClass extends NonNullNativeStruct {
    /** Gets the array class which encompass the current class. */
    @cache
    get arrayClass(): Il2Cpp.Class {
        return new Il2Cpp.Class(Il2Cpp.Api._classGetArrayClass(this, 1));
    }

    /** Gets the size of the object encompassed by the current array class. */
    @cache
    get arrayElementSize(): number {
        return Il2Cpp.Api._classGetArrayElementSize(this);
    }

    /** Gets the name of the assembly in which the current class is defined. */
    @cache
    get assemblyName(): string {
        return Il2Cpp.Api._classGetAssemblyName(this).readUtf8String()!;
    }

    /** Gets the class that declares the current nested class. */
    @cache
    get declaringClass(): Il2Cpp.Class | null {
        return getOrNull(Il2Cpp.Api._classGetDeclaringType(this), Il2Cpp.Class);
    }

    /** Gets the class of the object encompassed or referred to by the current array, pointer or reference class. */
    @cache
    get elementClass(): Il2Cpp.Class | null {
        return getOrNull(Il2Cpp.Api._classGetElementClass(this), Il2Cpp.Class);
    }

    /** Gets the amount of the fields of the current class. */
    @cache
    get fieldCount(): UInt64 {
        return Il2Cpp.Api._classGetFieldCount(this);
    }

    /** Gets the fields of the current class. */
    @cache
    get fields(): IterableRecord<Il2Cpp.Field> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Field> = {};

        let handle: NativePointer;
        let field: Il2Cpp.Field;

        while (!(handle = Il2Cpp.Api._classGetFields(this, iterator)).isNull()) {
            field = new Il2Cpp.Field(handle);
            record[field.name!] = field;
        }

        return makeIterable(addLevenshtein(record));
    }

    /** Gets the flags of the current class. */
    @cache
    get flags(): number {
        return Il2Cpp.Api._classGetFlags(this);
    }

    /** Gets the amount of generic parameters of this generic class. */
    @cache
    get genericParameterCount(): number {
        return Il2Cpp.Api._classGetGenericParameterCount(this);
    }

    /** Determines whether the current class has a class constructor. */
    @cache
    get hasClassConstructor(): boolean {
        return !!Il2Cpp.Api._classHasClassConstructor(this);
    }

    /** Determines whether the GC has tracking references to the current class instances. */
    @cache
    get hasReferences(): boolean {
        return !!Il2Cpp.Api._classHasReferences(this);
    }

    /** Gets the image in which the current class is defined. */
    @cache
    get image(): Il2Cpp.Image {
        return new Il2Cpp.Image(Il2Cpp.Api._classGetImage(this));
    }

    /** Gets the size of the instances of the current class. */
    @cache
    get instanceSize(): number {
        return Il2Cpp.Api._classGetInstanceSize(this);
    }

    /** Determines whether the current class is abstract. */
    @cache
    get isAbstract(): boolean {
        return !!Il2Cpp.Api._classIsAbstract(this);
    }

    /** Determines whether the current class is blittable. */
    @cache
    get isBlittable(): boolean {
        return !!Il2Cpp.Api._classIsBlittable(this);
    }

    /** Determines whether the current class is an enumeration. */
    @cache
    get isEnum(): boolean {
        return !!Il2Cpp.Api._classIsEnum(this);
    }

    /** Determines whether the current class is a generic one. */
    @cache
    get isGeneric(): boolean {
        return !!Il2Cpp.Api._classIsGeneric(this);
    }

    /** Determines whether the current class is inflated. */
    @cache
    get isInflated(): boolean {
        return !!Il2Cpp.Api._classIsInflated(this);
    }

    /** Determines whether the current class is an interface. */
    @cache
    get isInterface(): boolean {
        return !!Il2Cpp.Api._classIsInterface(this);
    }

    /** Determines whether the static constructor of the current class has been invoked. */
    get isStaticConstructorFinished(): boolean {
        return !!Il2Cpp.Api._classIsStaticConstructorFinished(this);
    }

    /** Determines whether the current class is a value type. */
    @cache
    get isValueType(): boolean {
        return !!Il2Cpp.Api._classIsValueType(this);
    }

    /** Gets the amount of the implemented or inherited interfaces by the current class. */
    @cache
    get interfaceCount(): number {
        return Il2Cpp.Api._classGetInterfaceCount(this);
    }

    /** Gets the interfaces implemented or inherited by the current class. */
    @cache
    get interfaces(): IterableRecord<Il2Cpp.Class> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Class> = {};

        let handle: NativePointer;
        let klass: Il2Cpp.Class;

        while (!(handle = Il2Cpp.Api._classGetInterfaces(this, iterator)).isNull()) {
            klass = new Il2Cpp.Class(handle);
            record[klass.type.name] = klass;
        }

        return makeIterable(addLevenshtein(record));
    }

    /** Gets the amount of the implemented methods by the current class. */
    @cache
    get methodCount(): number {
        return Il2Cpp.Api._classGetMethodCount(this);
    }

    /** Gets the methods implemented by the current class. */
    @cache
    get methods(): IterableRecord<Il2Cpp.Method> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Method> = preventKeyClash({});

        let handle: NativePointer;
        let method: Il2Cpp.Method;

        while (!(handle = Il2Cpp.Api._classGetMethods(this, iterator)).isNull()) {
            method = new Il2Cpp.Method(handle);
            record[method.name] = method;
        }

        return makeIterable(addLevenshtein(record));
    }

    /** Gets the name of the current class. */
    @cache
    get name(): string {
        return Il2Cpp.Api._classGetName(this).readUtf8String()!;
    }

    /** Gets the namespace of the current class. */
    @cache
    get namespace(): string {
        return Il2Cpp.Api._classGetNamespace(this).readUtf8String()!;
    }

    /** Gets the class from which the current class directly inherits. */
    @cache
    get parent(): Il2Cpp.Class | null {
        return getOrNull(Il2Cpp.Api._classGetParent(this), Il2Cpp.Class);
    }

    /** Gets the rank (number of dimensions) of the current array class. */
    @cache
    get rank(): number {
        return Il2Cpp.Api._classGetRank(this);
    }

    /** Gets a pointer to the static fields of the current class. */
    @cache
    get staticFieldsData(): NativePointer {
        return Il2Cpp.Api._classGetStaticFieldData(this);
    }

    /** */
    @cache
    get valueSize(): number {
        return Il2Cpp.Api._classGetValueSize(this, NULL);
    }

    /** Gets the type of the current class. */
    @cache
    get type(): Il2Cpp.Type {
        return new Il2Cpp.Type(Il2Cpp.Api._classGetType(this));
    }

    /** */
    getMethod(name: string, parametersCount: number = -1): Il2Cpp.Method | null {
        return getOrNull(Il2Cpp.Api._classGetMethodFromName(this, Memory.allocUtf8String(name), parametersCount), Il2Cpp.Method);
    }

    /** */
    inflate(...classes: Il2Cpp.Class[]): Il2Cpp.Class {
        if (!this.isGeneric) {
            raise(`Cannot inflate ${this.type.name} because it's not generic.`);
        }

        const types = classes.map(klass => klass.type.object);
        const typeArray = Il2Cpp.Array.from(Il2Cpp.Image.corlib.classes["System.Type"], types);
        
        // TODO: typeArray leaks
        return this.inflateRaw(typeArray);
    }

    /** @internal */
    inflateRaw(typeArray: Il2Cpp.Array<Il2Cpp.Object>): Il2Cpp.Class {
        const MakeGenericType = this.type.object.class.getMethod("MakeGenericType", 1)!

        let object = this.type.object;
        while (!object.class.equals(MakeGenericType.class)) object = object.base;

        const inflatedType = MakeGenericType.invokeRaw(object, typeArray);

        return new Il2Cpp.Class(Il2Cpp.Api._classFromSystemType(inflatedType as Il2Cpp.Object));
    }

    /** Calls the static constructor of the current class. */
    initialize(): void {
        Il2Cpp.Api._classInit(this);
    }

    /** Determines whether an instance of `other` class can be assigned to a variable of the current type. */
    isAssignableFrom(other: Il2Cpp.Class): boolean {
        return !!Il2Cpp.Api._classIsAssignableFrom(this, other);
    }

    /** Determines whether the current class derives from `other` class. */
    isSubclassOf(other: Il2Cpp.Class, checkInterfaces: boolean): boolean {
        return !!Il2Cpp.Api._classIsSubclassOf(this, other, +checkInterfaces);
    }

    override toString(): string {
        let fieldsString = "";
        let methodsString = "";

        for (const field of this.fields) fieldsString += "\n    " + field;
        for (const method of this.methods) methodsString += "\n    " + method;

        return (
            "// " +
            this.image.name +
            "\n" +
            (this.isEnum ? "enum" : this.isValueType ? "struct" : this.isInterface ? "interface" : "class") +
            " " +
            this.type.name +
            (this.parent != null || this.interfaceCount > 0 ? " : " : "") +
            (this.parent != null ? this.parent.type.name + (this.interfaceCount > 0 ? ", " : "") : "") +
            (this.interfaceCount > 0 ? Object.keys(this.interfaces).join(", ") : "") +
            "\n{" +
            fieldsString +
            (this.fieldCount.toNumber() > 0 && this.methodCount > 0 ? "\n" : "") +
            methodsString +
            "\n}\n\n"
        );
    }

    /** */
    @isEqualOrAbove("2019.3.0")
    static enumerate(block: (klass: Il2Cpp.Class) => void): void {
        const callback = new NativeCallback(
            function (klass: NativePointer, _: NativePointer): void {
                block(new Il2Cpp.Class(klass));
            },
            "void",
            ["pointer", "pointer"]
        );

        return Il2Cpp.Api._classForEach(callback, NULL);
    }
}

Il2Cpp.Class = Il2CppClass;

declare global {
    namespace Il2Cpp {
        class Class extends Il2CppClass {}
    }
}
