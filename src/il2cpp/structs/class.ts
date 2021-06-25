import { cache } from "decorator-cache-getter";

import { Accessor } from "../../utils/accessor";

import { Api } from "../api";
import { nonNullHandle } from "../decorators";
import { NativeStruct } from "../native-struct";
import { getOrNull } from "../utils";

import { _Il2CppField } from "./field";
import { _Il2CppGenericClass } from "./generic-class";
import { _Il2CppImage } from "./image";
import { _Il2CppMethod } from "./method";
import { _Il2CppType } from "./type";
import { _Il2CppTypeEnum } from "./type-enum";

/**
 * Represents a `Il2CppClass`.
 */
@nonNullHandle
export class _Il2CppClass extends NativeStruct {

    /**
     * Gets the array class which encompass the current class.
     */
    @cache
    get arrayClass(): _Il2CppClass {
        return new _Il2CppClass(Api._classGetArrayClass(this.handle, 1));
    }

    /**
     * Gets the size of the object encompassed by the current array class.
     */
    @cache
    get arrayElementSize(): number {
        return Api._classGetArrayElementSize(this.handle);
    }

    /**
     * Gets the name of the assembly in which the current class is defined.
     */
    @cache
    get assemblyName(): string {
        return Api._classGetAssemblyName(this.handle)!;
    }

    /**
     * Gets the class that declares the current nested class.
     */
    @cache
    get declaringClass(): _Il2CppClass | null {
        return getOrNull(Api._classGetDeclaringType(this.handle), _Il2CppClass);
    }

    /**
     * Gets the class of the object encompassed or referred to by the current array, pointer or reference class.
     */
    @cache
    get elementClass(): _Il2CppClass | null {
        return getOrNull(Api._classGetElementClass(this.handle), _Il2CppClass);
    }

    /**
     * Gets the amount of the fields of the current class.
     */
    @cache
    get fieldCount(): number {
        return Api._classGetFieldCount(this.handle);
    }

    /**
     * Gets the fields of the current class.
     */
    @cache
    get fields(): Accessor<_Il2CppField> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<_Il2CppField>();

        let handle: NativePointer;
        let field: _Il2CppField;

        while (!(handle = Api._classGetFields(this.handle, iterator)).isNull()) {
            field = new _Il2CppField(handle);
            accessor[field.name!] = field;
        }

        return accessor;
    }

    /**
     * Gets the generic class from which the current generic class can be constructed.
     */
    @cache
    get genericClass(): _Il2CppGenericClass | null {
        return getOrNull(Api._classGetGenericClass(this.handle), _Il2CppGenericClass);
    }

    /**
     * Determines whether the current class has a static constructor.
     */
    @cache
    get hasStaticConstructor(): boolean {
        return Api._classHasStaticConstructor(this.handle);
    }

    /**
     * Gets the image in which the current class is defined.
     */
    @cache
    get image(): _Il2CppImage {
        return new _Il2CppImage(Api._classGetImage(this.handle));
    }

    /**
     * Gets the of the instances of the current class.
     */
    @cache
    get instanceSize(): number {
        return Api._classGetInstanceSize(this.handle);
    }

    /**
     * Determines whether an instance of `other` class can be assigned to a variable of the current type.
     */
    isAssignableFrom(other: _Il2CppClass): boolean {
        return Api._classIsAssignableFrom(this.handle, other.handle);
    }

    /**
     * Determines whether the current class is an enumeration.
     */
    @cache
    get isEnum(): boolean {
        return Api._classIsEnum(this.handle);
    }

    /**
     * Determines whether the current class is an interface.
     */
    @cache
    get isInterface(): boolean {
        return Api._classIsInterface(this.handle);
    }

    /**
     * Determines whether the static constructor of the current class has been invoked.
     */
    get isStaticConstructorFinished(): boolean {
        return Api._classIsStaticConstructorFinished(this.handle);
    }

    /**
     * Determines whether the current class derives from `other` class.
     */
    isSubclassOf(other: _Il2CppClass, checkInterfaces: boolean): boolean {
        return Api._classIsSubclassOf(this.handle, other.handle, checkInterfaces);
    }

    /**
     * Determines whether the current class is an value type.
     */
    @cache
    get isValueType(): boolean {
        return Api._classIsValueType(this.handle) && !this.isEnum;
    }

    /**
     * Gets the amount of the implemented or inherited interfaces by the current class.
     */
    @cache
    get interfaceCount(): number {
        return Api._classGetInterfaceCount(this.handle);
    }

    /**
     * Gets the interfaces implemented or inherited by the current class.
     */
    @cache
    get interfaces(): Accessor<_Il2CppClass> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<_Il2CppClass>();

        let handle: NativePointer;
        let klass: _Il2CppClass;

        while (!(handle = Api._classGetInterfaces(this.handle, iterator)).isNull()) {
            klass = new _Il2CppClass(handle);
            accessor[klass.type.name] = klass;
        }

        return accessor;
    }

    /**
     * Gets the amount of the implemented methods by the current class.
     */
    @cache
    get methodCount(): number {
        return Api._classGetMethodCount(this.handle);
    }

    /**
     * Gets the methods implemented by the current class.
     */
    @cache
    get methods(): Accessor<_Il2CppMethod> {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<_Il2CppMethod>(true);

        let handle: NativePointer;
        let method: _Il2CppMethod;

        while (!(handle = Api._classGetMethods(this.handle, iterator)).isNull()) {
            method = new _Il2CppMethod(handle);
            accessor[method.name] = method;
        }

        return accessor;
    }

    /**
     * Gets the name of the current class.
     */
    @cache
    get name(): string {
        return Api._classGetName(this.handle)!;
    }

    /**
     * Gets the namespace of the current class.
     */
    @cache
    get namespace(): string {
        return Api._classGetNamespace(this.handle)!;
    }

    /**
     * Gets the class from which the current class directly inherits.
     */
    @cache
    get parent(): _Il2CppClass | null {
        return getOrNull(Api._classGetParent(this.handle), _Il2CppClass);
    }

    /**
     * Gets a pointer to the static fields of the current class.
     */
    @cache
    get staticFieldsData(): NativePointer {
        return Api._classGetStaticFieldData(this.handle);
    }

    /**
     * Gets the type of the current class.
     */
    @cache
    get type(): _Il2CppType {
        return new _Il2CppType(Api._classGetType(this.handle));
    }

    /**
     * Calls the static constructor of the current class.
     */
    initialize(): void {
        Api._classInit(this.handle);
    }

    /**
     * Traces every method invocation of the current class.
     */
    trace(): void {
        for (const method of this.methods) {
            method.trace();
        }
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
        for (const field of this.fields) {
            text += spacer + (this.isEnum && field.name != "value__" ? "" : field.type.name + " ") + field.name;
            if (field.isLiteral) {
                text += " = ";
                if (field.type.typeEnum == _Il2CppTypeEnum.STRING) text += '"';
                text += field.value;
                if (field.type.typeEnum == _Il2CppTypeEnum.STRING) text += '"';
            }
            text += this.isEnum && field.name != "value__" ? "," : "; // 0x" + field.offset.toString(16);
        }
        if (this.fieldCount + this.methodCount > 0) text += "\n";
        for (const method of this.methods) {
            text += spacer;
            if (!method.isInstance) text += "static ";
            text += method.returnType.name + " " + method.name + "(";
            for (const parameter of method.parameters) {
                if (parameter.position > 0) text += ", ";
                text += parameter.type.name + " " + parameter.name;
            }
            text += ");";
            if (!method.actualPointer.isNull()) text += " // " + method.relativePointerAsString + ";";
        }
        text += "\n}\n\n";
        return text;
    }
}
