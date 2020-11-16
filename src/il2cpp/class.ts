import Api from "./api";
import Il2CppMethod from "./method";
import Il2CppField from "./field";
import { Accessor } from "../utils/accessor";
import { lazy } from "../utils/decorators";
import Il2CppType from "./type";
import Il2CppImage from "./image";
import { getOrNull } from "../utils/helpers";
import { raise } from "../utils/console";

/** @internal */
export default class Il2CppClass {
    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
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
            accessor[method.name!] = method;
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
        if (this.hasStaticConstructor && !this.isStaticConstructorFinished) this.methods.cctor.invoke();
    }

    trace() {
        for (const method of this.methods) method.trace();
    }
}
