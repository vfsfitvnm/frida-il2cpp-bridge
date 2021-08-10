import { cache } from "decorator-cache-getter";

import { NonNullNativeStruct } from "../../utils/native-struct";
import { addLevenshtein, formatNativePointer, getOrNull, preventKeyClash } from "../../utils/utils";

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
    get fieldCount(): number {
        return Il2Cpp.Api._classGetFieldCount(this);
    }

    /** Gets the fields of the current class. */
    @cache
    get fields(): Readonly<Record<string, Il2Cpp.Field>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Field> = {};

        let handle: NativePointer;
        let field: Il2Cpp.Field;

        while (!(handle = Il2Cpp.Api._classGetFields(this, iterator)).isNull()) {
            field = new Il2Cpp.Field(handle);
            record[field.name!] = field;
        }

        return addLevenshtein(record);
    }

    /** Determines whether the current class has a class constructor. */
    @cache
    get hasClassConstructor(): boolean {
        return !!Il2Cpp.Api._classHasClassConstructor(this);
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

    /** */
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
    get interfaces(): Readonly<Record<string, Il2Cpp.Class>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Class> = {};

        let handle: NativePointer;
        let klass: Il2Cpp.Class;

        while (!(handle = Il2Cpp.Api._classGetInterfaces(this, iterator)).isNull()) {
            klass = new Il2Cpp.Class(handle);
            record[klass.type.name] = klass;
        }

        return addLevenshtein(record);
    }

    /** Gets the amount of the implemented methods by the current class. */
    @cache
    get methodCount(): number {
        return Il2Cpp.Api._classGetMethodCount(this);
    }

    /** Gets the methods implemented by the current class. */
    @cache
    get methods(): Readonly<Record<string, Il2Cpp.Method>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Method> = preventKeyClash({});

        let handle: NativePointer;
        let method: Il2Cpp.Method;

        while (!(handle = Il2Cpp.Api._classGetMethods(this, iterator)).isNull()) {
            method = new Il2Cpp.Method(handle);
            record[method.name] = method;
        }

        return addLevenshtein(record);
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

    /** Gets a pointer to the static fields of the current class. */
    @cache
    get staticFieldsData(): NativePointer {
        return Il2Cpp.Api._classGetStaticFieldData(this);
    }

    /** Gets the type of the current class. */
    @cache
    get type(): Il2Cpp.Type {
        return new Il2Cpp.Type(Il2Cpp.Api._classGetType(this));
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
        const spacer = "\n    ";
        let text = "// " + this.image.name + "\n";
        text += this.isEnum ? "enum" : this.isValueType ? "struct" : this.isInterface ? "interface" : "class";
        text += " " + this.type.name;
        if (this.parent != null || this.interfaceCount > 0) text += " : ";
        if (this.parent != null) {
            text += this.parent.type.name;
            if (this.interfaceCount > 0) text += ", ";
        }
        if (this.interfaceCount > 0) text += Object.keys(this.interfaces).join(", ");
        text += "\n{";
        for (const field of Object.values(this.fields)) {
            text += spacer;
            if (field.isStatic) text += "static ";
            text += field.type.name + " " + field.name;
            if (field.isLiteral) {
                if (field.type.class.isEnum) {
                    text += " = " + field.valueHandle.readS32();
                } else {
                    text += " = " + field.value;
                }
            }
            text += ";";
            if (!field.isLiteral) {
                text += " // 0x" + field.offset.toString(16);
            }
        }
        if (this.fieldCount && this.methodCount > 0) text += "\n";

        for (const method of Object.values(this.methods)) {
            text += spacer;
            if (method.isStatic) text += "static ";
            text += method.returnType.name + " " + method.name + "(";
            for (const parameter of Object.values(method.parameters)) {
                if (parameter.position > 0) text += ", ";
                text += parameter.type.name + " " + parameter.name;
            }
            text += ");";
            if (!method.virtualAddress.isNull()) text += " // " + formatNativePointer(method.relativeVirtualAddress);
        }
        text += "\n}\n\n";
        return text;
    }
}

Il2Cpp.Class = Il2CppClass;

declare global {
    namespace Il2Cpp {
        class Class extends Il2CppClass {}
    }
}
