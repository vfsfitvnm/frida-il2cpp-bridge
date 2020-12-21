import Api from "./api";
import Il2CppMethod from "./method";
import Il2CppField from "./field";
import { Accessor } from "../utils/accessor";
import { lazy } from "../utils/decorators";
import Il2CppType from "./type";
import Il2CppImage from "./image";
import { getOrNull } from "../utils/helpers";
import { raise } from "../utils/console";
import Il2CppTypeEnum from "./type-enum";

/** @internal */
export default class Il2CppClass {
    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get arrayClass() {
        return new Il2CppClass(Api._classGetArrayClass(this.handle, 1));
    }

    @lazy get arrayElementSize() {
        return Api._classGetArrayElementSize(this.handle);
    }

    @lazy get assemblyName() {
        return Api._classGetAssemblyName(this.handle)!;
    }

    @lazy get declaringClass() {
        return getOrNull(Api._classGetDeclaringType(this.handle), Il2CppClass);
    }

    @lazy get elementClass() {
        return getOrNull(Api._classGetElementClass(this.handle), Il2CppClass);
    }

    @lazy get fieldCount() {
        return Api._classGetFieldCount(this.handle);
    }

    @lazy get fields() {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<Il2CppField>();
        let handle: NativePointer;
        let field: Il2CppField;
        while (!(handle = Api._classGetFields(this.handle, iterator)).isNull()) {
            field = new Il2CppField(handle);
            accessor[field.name!] = field;
        }
        return accessor;
    }

    @lazy get hasStaticConstructor() {
        return Api._classHasStaticConstructor(this.handle);
    }

    @lazy get image() {
        return new Il2CppImage(Api._classGetImage(this.handle));
    }

    @lazy get instanceSize() {
        return Api._classGetInstanceSize(this.handle);
    }

    @lazy get isEnum() {
        return Api._classIsEnum(this.handle);
    }

    @lazy get isInterface() {
        return Api._classIsInterface(this.handle);
    }

    get isStaticConstructorFinished() {
        return Api._classIsStaticConstructorFinished(this.handle);
    }

    @lazy get isStruct() {
        return Api._classIsStruct(this.handle) && !this.isEnum;
    }

    @lazy get interfaceCount() {
        return Api._classGetInterfaceCount(this.handle);
    }

    @lazy get interfaces() {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<Il2CppClass>();
        let handle: NativePointer;
        let interfaze: Il2CppClass;
        while (!(handle = Api._classGetInterfaces(this.handle, iterator)).isNull()) {
            interfaze = new Il2CppClass(handle);
            accessor[interfaze.type.name] = interfaze;
        }
        return accessor;
    }

    @lazy get methodCount() {
        return Api._classGetMethodCount(this.handle);
    }

    @lazy get methods() {
        const iterator = Memory.alloc(Process.pointerSize);
        const accessor = new Accessor<Il2CppMethod>(true);
        let handle: NativePointer;
        let method: Il2CppMethod;
        while (!(handle = Api._classGetMethods(this.handle, iterator)).isNull()) {
            method = new Il2CppMethod(handle);
            accessor[method.name] = method;
        }
        return accessor;
    }

    @lazy get name() {
        return Api._classGetName(this.handle)!;
    }

    @lazy get namespace() {
        return Api._classGetNamespace(this.handle)!;
    }

    @lazy get parent() {
        return getOrNull(Api._classGetParent(this.handle), Il2CppClass);
    }

    @lazy get staticFieldsData() {
        return Api._classGetStaticFieldData(this.handle);
    }

    @lazy get type() {
        return new Il2CppType(Api._classGetType(this.handle));
    }

    ensureInitialized() {
        Api._classInit(this.handle);
    }

    trace() {
        for (const method of this.methods) method.trace();
    }

    toString() {
        const spacer = "\n    ";
        let text = "// " + this.image.name + "\n";
        text += this.isEnum ? "enum" : this.isStruct ? "struct" : this.isInterface ? "interface" : "class";
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
                if (field.type.typeEnum == Il2CppTypeEnum.STRING) text += '"';
                text += field.value;
                if (field.type.typeEnum == Il2CppTypeEnum.STRING) text += '"';
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
            if (!method.actualPointer.isNull()) text += "// " + method.actualPointer.sub(Api._library.base).toString() + ";";
        }
        text += "\n}\n\n";
        return text;
    }
}
