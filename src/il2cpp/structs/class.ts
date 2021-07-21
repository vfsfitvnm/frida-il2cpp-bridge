import { cache } from "decorator-cache-getter";

import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { addLevenshtein, preventKeyClash } from "../../utils/record";
import { getOrNull, NonNullNativeStruct } from "../../utils/native-struct";

@injectToIl2Cpp("Class")
class Il2CppClass extends NonNullNativeStruct {
    @cache
    get arrayClass(): Il2Cpp.Class {
        return new Il2Cpp.Class(Api._classGetArrayClass(this, 1));
    }

    @cache
    get arrayElementSize(): number {
        return Api._classGetArrayElementSize(this);
    }

    @cache
    get assemblyName(): string {
        return Api._classGetAssemblyName(this)!;
    }

    @cache
    get declaringClass(): Il2Cpp.Class | null {
        return getOrNull(Api._classGetDeclaringType(this), Il2Cpp.Class);
    }

    @cache
    get elementClass(): Il2Cpp.Class | null {
        return getOrNull(Api._classGetElementClass(this), Il2Cpp.Class);
    }

    @cache
    get fieldCount(): number {
        return Api._classGetFieldCount(this);
    }

    @cache
    get fields(): Readonly<Record<string, Il2Cpp.Field>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Field> = {};

        let handle: NativePointer;
        let field: Il2Cpp.Field;

        while (!(handle = Api._classGetFields(this, iterator)).isNull()) {
            field = new Il2Cpp.Field(handle);
            record[field.name!] = field;
        }

        return addLevenshtein(record);
    }

    @cache
    get hasStaticConstructor(): boolean {
        return Api._classHasStaticConstructor(this);
    }

    @cache
    get image(): Il2Cpp.Image {
        return new Il2Cpp.Image(Api._classGetImage(this));
    }

    @cache
    get instanceSize(): number {
        return Api._classGetInstanceSize(this);
    }

    @cache
    get isEnum(): boolean {
        return Api._classIsEnum(this);
    }

    @cache
    get isInterface(): boolean {
        return Api._classIsInterface(this);
    }

    get isStaticConstructorFinished(): boolean {
        return Api._classIsStaticConstructorFinished(this);
    }

    @cache
    get isValueType(): boolean {
        return Api._classIsValueType(this) && !this.isEnum;
    }

    @cache
    get interfaceCount(): number {
        return Api._classGetInterfaceCount(this);
    }

    @cache
    get interfaces(): Readonly<Record<string, Il2Cpp.Class>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Class> = {};

        let handle: NativePointer;
        let klass: Il2Cpp.Class;

        while (!(handle = Api._classGetInterfaces(this, iterator)).isNull()) {
            klass = new Il2Cpp.Class(handle);
            record[klass.type.name] = klass;
        }

        return addLevenshtein(record);
    }

    @cache
    get methodCount(): number {
        return Api._classGetMethodCount(this);
    }

    @cache
    get methods(): Readonly<Record<string, Il2Cpp.Method>> {
        const iterator = Memory.alloc(Process.pointerSize);
        const record: Record<string, Il2Cpp.Method> = preventKeyClash({});

        let handle: NativePointer;
        let method: Il2Cpp.Method;

        while (!(handle = Api._classGetMethods(this, iterator)).isNull()) {
            method = new Il2Cpp.Method(handle);
            record[method.name] = method;
        }

        return addLevenshtein(record);
    }

    @cache
    get name(): string {
        return Api._classGetName(this)!;
    }

    @cache
    get namespace(): string {
        return Api._classGetNamespace(this)!;
    }

    @cache
    get parent(): Il2Cpp.Class | null {
        return getOrNull(Api._classGetParent(this), Il2Cpp.Class);
    }

    @cache
    get staticFieldsData(): NativePointer {
        return Api._classGetStaticFieldData(this);
    }

    @cache
    get type(): Il2Cpp.Type {
        return new Il2Cpp.Type(Api._classGetType(this));
    }

    isAssignableFrom(other: Il2Cpp.Class): boolean {
        return Api._classIsAssignableFrom(this, other);
    }

    isSubclassOf(other: Il2Cpp.Class, checkInterfaces: boolean): boolean {
        return Api._classIsSubclassOf(this, other, checkInterfaces);
    }

    initialize(): void {
        Api._classInit(this);
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
            if (field.isStatic && !this.isEnum) text += "static ";
            text += (this.isEnum && field.name != "value__" ? "" : field.type.name + " ") + field.name;
            if (field.isLiteral) {
                text += " = ";
                if (field.type.typeEnum == "string") text += '"';
                text += field.value;
                if (field.type.typeEnum == "string") text += '"';
            }
            text += this.isEnum && field.name != "value__" ? "," : "; // 0x" + field.offset.toString(16);
        }
        if (this.fieldCount + this.methodCount > 0) text += "\n";
        for (const method of Object.values(this.methods)) {
            text += spacer;
            if (method.isStatic) text += "static ";
            text += method.returnType.name + " " + method.name + "(";
            for (const parameter of Object.values(method.parameters)) {
                if (parameter.position > 0) text += ", ";
                text += parameter.type.name + " " + parameter.name;
            }
            text += ");";
            if (!method.pointer.isNull()) text += " // " + method.relativePointerAsString + ";";
        }
        text += "\n}\n\n";
        return text;
    }
}
