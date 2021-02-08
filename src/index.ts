import UnityVersion from "./utils/unity-version";
import { forLibrary, il2CppLibraryName, unityLibraryName } from "./utils/platform";
import { inform, ok, raise, warn } from "./utils/console";
import { cache } from "decorator-cache-getter";
import Api from "./api";
import { Accessor, filterAndMap } from "./utils/accessor";
import { getOrNull } from "./utils/helpers";

const JSObject = Object;

const JSArray = Array;

async function getUnityVersion() {
    let unityVersion: UnityVersion | undefined;
    const searchStringHex = "45787065637465642076657273696f6e3a"; // "Expected version: "
    try {
        const unityLibrary = await forLibrary(unityLibraryName);
        for (const range of unityLibrary.enumerateRanges("r--")) {
            const result = Memory.scanSync(range.base, range.size, searchStringHex)[0];
            if (result !== undefined) {
                unityVersion = new UnityVersion(result.address.readUtf8String()!);
                break;
            }
        }
    } catch (e) {
        raise("Couldn't obtain the Unity version: " + e);
    }
    if (!unityVersion) raise("Couldn't obtain the Unity version.");

    return unityVersion;
}

/**
 * Everything is exposed through this global object.\
 * Every `Il2Cpp.${...}` class has a `handle` property, which is its `NativePointer`.
 */
module Il2Cpp {
    /**
     * The Il2Cpp library (`libil2cpp.so`, `GameAssembly.dll` ...).
     */
    export let library: Module;

    /**
     * The Unity version of the current application.
     */
    export let unityVersion: UnityVersion;

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
    export async function initialize() {
        library = await forLibrary(il2CppLibraryName);
        unityVersion = await getUnityVersion();
        Api.initSources(library, unityVersion);
    }

    /**
     * Performs a dump of the assemblies.\
     * It's implemented is pure JS (which is a lot slower than the `CModule`
     * implementation).
     * Since `QuickJS` is not mature yet (and not ready for string concatenation),
     * remember to pick `V8` instead.
     * ```typescript
     * const Application = domain.assemblies["UnityEngine.CoreModule"].image.classes["UnityEngine.Application"];
     * const version = Application.methods.get_version.invoke();
     * const identifier = Application.methods.get_identifier.invoke();
     * const persistentDataPath = Application.methods.get_persistentDataPath.invoke();
     * Il2Cpp.dump(domain, `${persistentDataPath}/${identifier}_${version}.cs`);
     * ```
     * @param domain The application {@link Il2Cpp.Domain | domain}.
     * @param filename Where to save the dump. The caller has to
     * make sure the application has a write permission for that location.
     *
     */
    export function dump(domain: Domain, filename: string) {
        let content = "";
        for (const assembly of domain.assemblies) {
            inform(`Dumping ${assembly.name}...`);
            for (const klass of assembly.image.classes) content += klass.toString();
        }

        const file = new File(filename, "w");
        file.write(content);
        file.flush();
        file.close();
        ok(`Dump saved to ${filename}.`);
    }

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
    export function choose<T extends Object | String | Array<AllowedType> = Object>(klass: Class): T[] {
        const isString = klass.type.typeEnum == TypeEnum.STRING;
        const isArray = klass.type.typeEnum == TypeEnum.SZARRAY;

        const matches: T[] = [];

        const callback = (objects: NativePointer, size: number, userData: NativePointer) => {
            for (let i = 0; i < size; i++) {
                const pointer = objects.add(i * Process.pointerSize).readPointer();

                if (isString) matches.push(new Il2Cpp.String(pointer) as T);
                else if (isArray) matches.push(new Array(pointer) as T);
                else matches.push(new Object(pointer) as T);
            }
        };

        const chooseCallback = new NativeCallback(callback, "void", ["pointer", "int", "pointer"]);
        const onWorld = new NativeCallback(() => {}, "void", []);

        const state = Api._livenessCalculationBegin(klass.handle, 0, chooseCallback, NULL, onWorld, onWorld);
        Api._livenessCalculationFromStatics(state);
        Api._livenessCalculationEnd(state);

        return matches;
    }

    /**
     * It takes a memory snapshot and scans the current tracked objects of the given class.\
     * It leads to different results if compared to {@link Il2Cpp.choose | choose}.
     * @template T Type parameter to automatically cast the objects to other object-like
     * entities, like string and arrays. Default is {@link Il2Cpp.Object | Object}.
     * @param klass The class of the objects you are looking for.
     * @return An array of ready-to-use objects, strings or arrays. Value types are boxed.
     */
    export function choose2<T extends Object | String | Array<AllowedType> = Object>(klass: Class): T[] {
        const isString = klass.type.typeEnum == TypeEnum.STRING;
        const isArray = klass.type.typeEnum == TypeEnum.SZARRAY;

        const matches: T[] = [];

        const snapshot = MemorySnapshot.capture();
        const count = snapshot.trackedObjectCount;
        const start = snapshot.objectsPointer;

        for (let i = 0; i < count; i++) {
            const pointer = start.add(i * Process.pointerSize).readPointer();
            const object = new Object(pointer);

            if (object.class.handle.equals(klass.handle)) {
                if (isString) matches.push(new Il2Cpp.String(pointer) as T);
                else if (isArray) matches.push(new Array(pointer) as T);
                else matches.push(object as T);
            }
        }

        snapshot.free();

        return matches;
    }

    /**
     * Represents something which has an accessible value.
     */
    export interface Valuable {
        /**
         * The actual "pretty" value.
         */
        value: AllowedType;
        /**
         * The actual location.
         */
        valueHandle: NativePointer;
    }

    /**
     * Represents an invokable method.
     */
    export interface Invokable {
        /**
         * See {@link Il2Cpp.Method.invoke | invoke}.
         */
        invoke<T extends AllowedType>(...parameters: AllowedType[]): T;
    }

    /**
     * Represents a `Il2CppDomain`.
     * ```typescript
     * assert(domain.name == "IL2CPP Root Domain");
     * ```
     */
    export class Domain {
        /** @internal */
        private static instance: Domain;

        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /**
         * @return Its name. Probably `IL2CPP Root Domain`.
         */
        @cache get name() {
            return Api._domainGetName(this.handle);
        }

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
        @cache get assemblies() {
            const accessor = new Accessor<Assembly>();

            const sizePointer = Memory.alloc(Process.pointerSize);
            const startPointer = Api._domainGetAssemblies(NULL, sizePointer);

            if (startPointer.isNull()) {
                raise("First assembly pointer is NULL.");
            }

            const count = sizePointer.readInt();

            for (let i = 0; i < count; i++) {
                const assembly = new Assembly(startPointer.add(i * Process.pointerSize).readPointer());
                accessor[assembly.name!] = assembly;
            }
            return accessor;
        }

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
        static async get() {
            if (this.instance == undefined) {
                const domainPointer = await new Promise<NativePointer>(resolve => {
                    const start = Api._domainGetAssemblies(NULL, Memory.alloc(Process.pointerSize));
                    if (!start.isNull()) {
                        resolve(Api._domainGet());
                    } else {
                        const interceptor = Interceptor.attach(Api._init, {
                            onLeave() {
                                setTimeout(() => interceptor.detach());
                                resolve(Api._domainGet());
                            }
                        });
                    }
                });
                this.instance = new Domain(domainPointer);
                Api._threadAttach(this.instance.handle);
            }
            return this.instance;
        }
    }

    /**
     * Represents a `Il2CppAssembly`.
     * ```typescript
     * const mscorlibAssembly = domain.assemblies.mscorlib;
     * assert(mscorlibAssembly.name == "mscorlib");
     * ```
     */
    export class Assembly {
        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /**
         * @return Its image.
         */
        @cache get image() {
            return new Image(Api._assemblyGetImage(this.handle));
        }

        /**
         * @return Its name.
         */
        @cache get name() {
            if (unityVersion.isEqualOrAbove_2018_1_0) {
                return Api._assemblyGetName(this.handle)!;
            }
            return this.image.name.replace(".dll", "");
        }
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
    export class Image {
        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /**
         * @return The count of its classes.
         */
        @cache get classCount() {
            return Api._imageGetClassCount(this.handle);
        }

        /**
         * Non-generic types are stored in sequence.
         * @return The start index of its classes, `-1` if this information
         * is not available - since Unity version `2020.2.0`.
         */
        @cache get classStart() {
            return unityVersion.isBelow_2020_2_0 ? Api._imageGetClassStart(this.handle) : -1;
        }

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
        @cache get classes() {
            const accessor = new Accessor<Class>();
            const start = this.classStart;
            if (unityVersion.isEqualOrAbove_2018_3_0) {
                const end = this.classCount;
                for (let i = 0; i < end; i++) {
                    const klass = new Class(Api._imageGetClass(this.handle, i));
                    accessor[klass.type.name] = klass;
                }
            } else {
                const end = start + this.classCount;
                const globalIndex = Memory.alloc(Process.pointerSize);
                globalIndex.add(Type.offsetOfTypeEnum).writeInt(0x20);
                for (let i = start; i < end; i++) {
                    const klass = new Class(Api._typeGetClassOrElementClass(globalIndex.writeInt(i)));
                    accessor[klass.type!.name!] = klass;
                }
            }
            return accessor;
        }

        /**
         * @return Its name, equals to the name of its assembly plus its
         * extension.
         */
        @cache get name() {
            return Api._imageGetName(this.handle)!;
        }

        /**
         * @param namespace The class namespace.
         * @param name The class name.
         * @return The class for the given namespace and name or `null` if
         * not found.
         */
        getClassFromName(namespace: string, name: string) {
            return getOrNull(Api._classFromName(this.handle, namespace, name), Class);
        }
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
    export class Class {
        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /**
         * The inverse of {@link Il2Cpp.Class.elementClass | elementClass}.
         * @return The array class which has the caller as element class.
         */
        @cache get arrayClass() {
            return new Class(Api._classGetArrayClass(this.handle, 1));
        }

        /**
         * @return The size as array element.
         */
        @cache get arrayElementSize() {
            return Api._classGetArrayElementSize(this.handle);
        }

        /**
         * @returns The name of the assembly it belongs to.
         */
        @cache get assemblyName() {
            return Api._classGetAssemblyName(this.handle)!;
        }

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
        @cache get declaringClass() {
            return getOrNull(Api._classGetDeclaringType(this.handle), Class);
        }

        /**
         * Its element class if it's an array.
         */
        @cache get elementClass() {
            return getOrNull(Api._classGetElementClass(this.handle), Class);
        }

        /**
         * @return The count of its fields.
         */
        @cache get fieldCount() {
            return Api._classGetFieldCount(this.handle);
        }

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
        @cache get fields() {
            const iterator = Memory.alloc(Process.pointerSize);
            const accessor = new Accessor<Field>();
            let handle: NativePointer;
            let field: Field;
            while (!(handle = Api._classGetFields(this.handle, iterator)).isNull()) {
                field = new Field(handle);
                accessor[field.name!] = field;
            }
            return accessor;
        }

        /**
         * @return `true` if it has a static constructor, `false` otherwise.
         */
        @cache get hasStaticConstructor() {
            return Api._classHasStaticConstructor(this.handle);
        }

        /**
         * @return The image it belongs to.
         */
        @cache get image() {
            return new Image(Api._classGetImage(this.handle));
        }

        /**
         * @return The size of its instance.
         */
        @cache get instanceSize() {
            return Api._classGetInstanceSize(this.handle);
        }

        /**
         * @return `true` if it's an `enum`, `false` otherwise.
         */
        @cache get isEnum() {
            return Api._classIsEnum(this.handle);
        }

        /**
         * @return `true` if it's an `interface`, `false` otherwise.
         */
        @cache get isInterface() {
            return Api._classIsInterface(this.handle);
        }

        /**
         * @return `true` If its static constructor has been already called,
         * so if its static data has been initialized, `false` otherwise.
         */
        get isStaticConstructorFinished() {
            return Api._classIsStaticConstructorFinished(this.handle);
        }

        /**
         * @return `true` if it's a value type (aka struct), `false` otherwise.
         */
        @cache get isStruct() {
            return Api._classIsStruct(this.handle) && !this.isEnum;
        }

        /**
         * @return The count of its implemented interfaces.
         */
        @cache get interfaceCount() {
            return Api._classGetInterfaceCount(this.handle);
        }

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
        @cache get interfaces() {
            const iterator = Memory.alloc(Process.pointerSize);
            const accessor = new Accessor<Class>();
            let handle: NativePointer;
            let interfaze: Class;
            while (!(handle = Api._classGetInterfaces(this.handle, iterator)).isNull()) {
                interfaze = new Class(handle);
                accessor[interfaze.type.name] = interfaze;
            }
            return accessor;
        }

        /**
         * @return The count of its methods.
         */
        @cache get methodCount() {
            return Api._classGetMethodCount(this.handle);
        }

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
        @cache get methods() {
            const iterator = Memory.alloc(Process.pointerSize);
            const accessor = new Accessor<Method>(true);
            let handle: NativePointer;
            let method: Method;
            while (!(handle = Api._classGetMethods(this.handle, iterator)).isNull()) {
                method = new Method(handle);
                accessor[method.name] = method;
            }
            return accessor;
        }

        /**
         * @return Its name.
         */
        @cache get name() {
            return Api._classGetName(this.handle)!;
        }

        /**
         * @return Its namespace.
         */
        @cache get namespace() {
            return Api._classGetNamespace(this.handle)!;
        }

        /**
         * @return Its parent if there is, `null.` otherwise.
         */
        @cache get parent() {
            return getOrNull(Api._classGetParent(this.handle), Class);
        }

        /**
         * @return A pointer to its static fields.
         */
        @cache get staticFieldsData() {
            return Api._classGetStaticFieldData(this.handle);
        }

        /**
         * @return Its type.
         */
        @cache get type() {
            return new Type(Api._classGetType(this.handle));
        }

        /**
         * It makes sure its static data has been initialized.\
         * See {@link isStaticConstructorFinished} for an example.
         */
        ensureInitialized() {
            Api._classInit(this.handle);
        }

        /**
         * It traces all its methods.\
         * See {@link Method.trace | trace} for more details.
         */
        trace() {
            for (const method of this.methods) method.trace();
        }

        /**
         * @return The class dump (used by {@link Il2Cpp.dump | dump}).
         */
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
            if (this.interfaceCount > 0) text += JSObject.keys(this.interfaces).join(", ");
            text += "\n{";
            for (const field of this.fields) {
                text += spacer + (this.isEnum && field.name != "value__" ? "" : field.type.name + " ") + field.name;
                if (field.isLiteral) {
                    text += " = ";
                    if (field.type.typeEnum == TypeEnum.STRING) text += '"';
                    text += field.value;
                    if (field.type.typeEnum == TypeEnum.STRING) text += '"';
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
                if (!method.actualPointer.isNull()) text += "// " + method.relativePointerAsString + ";";
            }
            text += "\n}\n\n";
            return text;
        }
    }

    /**
     * Represents a `Il2CppGenericClass`.
     */
    export class GenericClass {
        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /**
         * @return Its class.
         */
        @cache get cachedClass() {
            return getOrNull(Api._genericClassGetCachedClass(this.handle), Class);
        }
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
    export class Field implements Valuable {
        /** @internal */
        private static readonly THREAD_STATIC_FIELD_OFFSET = -1;

        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /**
         * @return The class it belongs to.
         */
        @cache get class() {
            return new Class(Api._fieldGetClass(this.handle));
        }

        /**
         * @return `true` if it's a instance field, `false` otherwise.
         */
        @cache get isInstance() {
            return Api._fieldIsInstance(this.handle);
        }

        /**
         * @return `true` if it's literal field, `false` otherwise.
         */
        @cache get isLiteral() {
            return Api._fieldIsLiteral(this.handle);
        }

        /**
         * @return `true` if it's a thread  field, `false` otherwise.
         */
        @cache get isThreadStatic() {
            return this.offset == Field.THREAD_STATIC_FIELD_OFFSET;
        }

        /**
         * @return Its name.
         */
        @cache get name() {
            return Api._fieldGetName(this.handle)!;
        }

        /**
         * A static field offsets is meant as the offset between it's class
         * {@link Class.staticFieldsData | staticFieldsData} and its location.
         * A static field offsets is meant as the offset between it's object
         * {@link Object.handle | handle} and its location.
         * @return Its offset.
         */
        @cache get offset() {
            return Api._fieldGetOffset(this.handle);
        }

        /**
         * @return Its type.
         */
        @cache get type() {
            return new Type(Api._fieldGetType(this.handle));
        }

        /**
         * @return Its value.
         */
        get value() {
            return readFieldValue(this.valueHandle, this.type!);
        }

        /**
         * NOTE: Thread static or literal values cannot be altered yet.
         * @param v Its new value.
         */
        set value(v) {
            if (this.isInstance) {
                raise(`Cannot access the instance field "${this.name}" without an instance.`);
            } else if (this.isThreadStatic || this.isLiteral) {
                raise(`Cannot edit the thread static or literal field "${this.name}".`);
            }
            writeFieldValue(this.valueHandle, v, this.type!);
        }

        /**
         * @return The actual location of its value.
         */
        get valueHandle() {
            let handle: NativePointer;
            if (this.isInstance) {
                raise(`Cannot access the instance field "${this.name}" without an instance.`);
            } else if (this.isThreadStatic || this.isLiteral) {
                handle = Memory.alloc(Process.pointerSize);
                Api._fieldGetStaticValue(this.handle, handle);
            } else {
                handle = this.class.staticFieldsData.add(this.offset);
            }
            return handle;
        }

        asHeld(handle: NativePointer) {
            if (!this.isInstance) {
                raise(`"${this.name}" is a static field.`);
            }
            const type = this.type;
            return {
                valueHandle: handle,
                get value() {
                    return readFieldValue(handle, type);
                },
                set value(v) {
                    writeFieldValue(handle, v, type);
                }
            } as Valuable;
        }
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
     * assert(BooleanClass.methods.Parse.invoke<boolean>(String.from("true")));
     * ```
     */
    export class Method {
        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /**
         * ```typescript
         * const MathClass = mscorlib.classes["System.Math"];
         * Interceptor.attach(MathClass.actualPointer, {
         *     // ...
         * });
         * ```
         * @return Its actual pointer in memory.
         */
        @cache get actualPointer() {
            return Api._methodGetPointer(this.handle);
        }

        /**
         * @return The class it belongs to.
         */
        @cache get class() {
            return new Class(Api._methodGetClass(this.handle));
        }

        /**
         * @return `true` if it's generic, `false` otherwise.
         */
        @cache get isGeneric() {
            return Api._methodIsGeneric(this.handle);
        }

        /**
         * @return `true` if it's inflated (a generic with a concrete type parameter),
         * false otherwise.
         */
        @cache get isInflated() {
            return Api._methodIsInflated(this.handle);
        }

        /**
         *  @return `true` if it's an instance method, `false` otherwise.
         */
        @cache get isInstance() {
            return Api._methodIsInstance(this.handle);
        }

        /**
         * @return Its name.
         */
        @cache get name() {
            return Api._methodGetName(this.handle)!;
        }

        /**
         * @return The count of its parameters.
         */
        @cache get parameterCount() {
            return Api._methodGetParamCount(this.handle);
        }

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
        @cache get parameters() {
            const iterator = Memory.alloc(Process.pointerSize);
            const accessor = new Accessor<Parameter>();
            let handle: NativePointer;
            let parameter: Parameter;
            while (!(handle = Api._methodGetParameters(this.handle, iterator)).isNull()) {
                parameter = new Parameter(handle);
                accessor[parameter.name!] = parameter;
            }
            return accessor;
        }

        /**
         * @return Its static fixed offset, useful for static analysis.
         */
        @cache get relativePointerAsString() {
            return `0x${this.actualPointer.sub(library.base).toString(16).padStart(8, "0")}`;
        }

        /**
         * @return Its return type.
         */
        @cache get returnType() {
            return new Type(Api._methodGetReturnType(this.handle));
        }

        /** @internal */
        @cache get nativeFunction() {
            const parametersTypesAliasesForFrida = new JSArray(this.parameterCount).fill("pointer");
            if (this.isInstance || unityVersion.isBelow_2018_3_0) {
                parametersTypesAliasesForFrida.push("pointer");
            }
            if (this.isInflated) {
                parametersTypesAliasesForFrida.push("pointer");
            }
            return new NativeFunction(this.actualPointer, this.returnType.aliasForFrida, parametersTypesAliasesForFrida);
        }

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
        set implementation(callback: ImplementationCallback | null) {
            Interceptor.revert(this.actualPointer);

            if (callback == null) return;

            if (this.actualPointer.isNull()) {
                raise(`Can't replace method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
            }

            const parametersTypesAliasesForFrida = [];
            if (this.isInstance) {
                parametersTypesAliasesForFrida.push(this.class.type.aliasForFrida);
            }
            for (const parameterInfo of this.parameters) {
                parametersTypesAliasesForFrida.push(parameterInfo.type.aliasForFrida);
            }
            const methodInfo = this;

            const replaceCallback: NativeCallbackImplementation = function (...invocationArguments: any[]) {
                const instance = methodInfo.isInstance ? new Object(invocationArguments[0]) : null;
                const startIndex = +methodInfo.isInstance | unityVersion.isBelow_2018_3_0;
                const args = methodInfo.parameters[filterAndMap](
                    () => true,
                    parameter => parameter.asHeld(invocationArguments, startIndex)
                );
                return callback.call(this!, instance, args);
            };

            const nativeCallback = new NativeCallback(replaceCallback, this.returnType.aliasForFrida, parametersTypesAliasesForFrida);

            Interceptor.replace(this.actualPointer, nativeCallback);
        }

        /** @internal */
        @cache get parametersTypesAliasesForFrida() {
            const parametersTypesAliasesForFrida = new JSArray(this.parameterCount).fill("pointer");
            if (this.isInstance || unityVersion.isBelow_2018_3_0) {
                parametersTypesAliasesForFrida.push("pointer");
            }
            if (this.isInflated) {
                parametersTypesAliasesForFrida.push("pointer");
            }
            return parametersTypesAliasesForFrida;
        }

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
        invoke<T extends AllowedType>(...parameters: AllowedType[]) {
            if (this.isInstance) {
                raise(`Cannot invoke the instance method "${this.name}" without an instance.`);
            }
            return this._invoke(NULL, ...parameters);
        }

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
        intercept({ onEnter, onLeave }: { onEnter?: OnEnterCallback; onLeave?: OnLeaveCallback }) {
            if (this.actualPointer.isNull()) {
                raise(`Can't intercept method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
            }

            const interceptorCallbacks: ScriptInvocationListenerCallbacks = {};

            if (onEnter != undefined) {
                const methodInfo = this;
                interceptorCallbacks.onEnter = function (invocationArguments) {
                    const instance = methodInfo.isInstance ? new Object(invocationArguments[0]) : null;
                    const startIndex = +methodInfo.isInstance | unityVersion.isBelow_2018_3_0;
                    const args = methodInfo.parameters[filterAndMap](
                        () => true,
                        parameter => parameter.asHeld(invocationArguments, startIndex)
                    );
                    onEnter.call(this, instance, args);
                };
            }

            if (onLeave != undefined) {
                const methodInfo = this;
                interceptorCallbacks.onLeave = function (invocationReturnValue) {
                    onLeave.call(this, {
                        valueHandle: invocationReturnValue.add(0),
                        get value() {
                            return readRawValue(invocationReturnValue, methodInfo.returnType);
                        },
                        set value(v) {
                            invocationReturnValue.replace(allocRawValue(v, methodInfo.returnType));
                        }
                    } as Valuable);
                };
            }

            return Interceptor.attach(this.actualPointer, interceptorCallbacks);
        }

        /**
         * Prints a message when the method is invoked.
         * ```typescript
         * TODO
         * ```
         */
        trace() {
            if (this.actualPointer.isNull()) {
                warn(`Can't trace method ${this.name} from ${this.class.type.name}: pointer is NULL.`);
            }
            try {
                Interceptor.attach(this.actualPointer, () => inform(`${this.relativePointerAsString} ${this.name}`));
            } catch (e) {
                warn(`Can't trace method ${this.name} from ${this.class.type.name}: ${e.message}.`);
            }
        }

        /** @internal */
        asHeld(holder: NativePointer) {
            if (!this.isInstance) {
                raise(`"${this.name}" is a static method.`);
            }
            const invoke = this._invoke.bind(this, holder);
            return {
                invoke<T extends AllowedType>(...parameters: AllowedType[]) {
                    return invoke(...parameters) as T;
                }
            } as Invokable;
        }

        /** @internal */
        private _invoke(instance: NativePointer, ...parameters: AllowedType[]) {
            if (this.parameterCount != parameters.length) {
                raise(`This method takes ${this.parameterCount} parameters, but ${parameters.length} were supplied.`);
            }
            const allocatedParameters = JSArray.from(this.parameters).map((parameter, i) => allocRawValue(parameters[i], parameter.type));

            if (this.isInstance || unityVersion.isBelow_2018_3_0) allocatedParameters.unshift(instance);
            if (this.isInflated) allocatedParameters.push(this.handle);

            return readRawValue(this.nativeFunction(...allocatedParameters) as NativePointer, this.returnType);
        }
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
    export class Parameter {
        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /**
         * @return Its name.
         */
        @cache get name() {
            return Api._parameterGetName(this.handle)!;
        }

        /**
         * @return Its position.
         */
        @cache get position() {
            return Api._parameterGetPosition(this.handle);
        }

        /**
         *  @return Its type.
         */
        @cache get type() {
            return new Type(Api._parameterGetType(this.handle));
        }

        /** @internal */
        asHeld(holder: InvocationArguments, startIndex: number) {
            const position = this.position;
            const type = this.type;
            return {
                valueHandle: holder[startIndex + position],
                get value() {
                    return readRawValue(holder[startIndex + position], type);
                },
                set value(v) {
                    holder[startIndex + position] = allocRawValue(v, type);
                }
            } as Valuable;
        }
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
    export class ValueType {
        /** @internal */
        constructor(readonly handle: NativePointer, readonly klass: Class) {}

        /**
         * NOTE: the class is hardcoded when a new instance is created.\
         * It's not completely reliable.
         * @return Its class.
         */
        get class() {
            return this.klass;
        }

        /**
         * @return Its fields.
         */
        @cache get fields() {
            return this.class.fields[filterAndMap](
                field => field.isInstance,
                field => field.asHeld(this.handle.add(field.offset).sub(Object.headerSize))
            );
        }

        /**
         * See {@link Il2Cpp.Object.unbox} for an example.
         * @return The boxed value type.
         */
        box() {
            return new Object(Api._valueBox(this.klass.handle, this.handle));
        }
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
    export class Object {
        /**
         * @param handle It's `NativePointer`.
         */
        constructor(readonly handle: NativePointer) {}

        /** @internal */
        @cache
        static get headerSize() {
            return Api._objectGetHeaderSize();
        }

        /**
         * @return The same object as an instance of its parent.
         */
        @cache get base() {
            if (this.class.parent == null) {
                raise(`Class "${this.class.type.name}" has no parent.`);
            }

            const object = new Object(this.handle);
            Reflect.defineProperty(object, "class", { get: () => this.class.parent! });
            return object;
        }

        /**
         * @return Its class.
         */
        @cache get class() {
            return new Class(Api._objectGetClass(this.handle));
        }

        /**
         * See {@link Class.fields} for an example.
         * @return Its fields.
         */
        @cache get fields() {
            return this.class.fields[filterAndMap](
                field => field.isInstance,
                field => field.asHeld(this.handle.add(field.offset))
            );
        }

        /**
         * See {@link Il2Cpp.Class.methods} for an example.
         * @return Its methods.
         */
        @cache get methods() {
            return this.class.methods[filterAndMap](
                method => method.isInstance,
                method => method.asHeld(this.handle)
            );
        }

        /**
         * NOTE: the object will be allocated only.
         * @param klass The class of the object to allocate.
         * @return A new object.
         */
        static from(klass: Class) {
            return new Object(Api._objectNew(klass.handle));
        }

        /**
         * @return The unboxed value type.
         */
        unbox() {
            if (!this.class.isStruct) raise(`Cannot unbox a non value type object of class "${this.class.type.name}"`);
            return new ValueType(Api._objectUnbox(this.handle), this.class);
        }
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
     * assert(str.object.class.type.typeEnum == TypeEnum.STRING);
     * ```
     */
    export class String {
        /** @internal */
        constructor(readonly handle: NativePointer) {}

        /**
         * @return Its actual content.
         */
        get content() {
            return Api._stringChars(this.handle).readUtf16String(this.length);
        }

        /**
         * @param value The new content.
         */
        set content(value) {
            if (value != null) {
                Api._stringChars(this.handle).writeUtf16String(value);
                Api._stringSetLength(this.handle, value.length);
            }
        }

        /**
         * @return Its length.
         */
        get length() {
            return Api._stringLength(this.handle);
        }

        /**
         * @return The same string as an object.
         */
        get object() {
            return new Object(this.handle);
        }

        /**
         * Creates a new string.
         * @param content The string content.
         * @return A new string.
         */
        static from(content: string) {
            return new Il2Cpp.String(Api._stringNew(content));
        }

        /**
         * @return The string content.
         */
        toString() {
            return this.content;
        }
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
    export class Array<T extends AllowedType> implements Iterable<T> {
        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (this.handle.isNull()) {
                raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
            }
        }

        /**
         * @return The size of each element.
         */
        @cache get elementSize() {
            return this.object.class.type.dataType!.class.arrayElementSize;
        }

        /**
         * @return The type of its elements.
         */
        @cache get elementType() {
            return this.object.class.type.dataType!;
        }

        /** @internal */
        @cache get elements() {
            return Api._arrayGetElements(this.handle);
        }

        /**
         * @return Its length.
         */
        @cache get length() {
            return Api._arrayGetLength(this.handle);
        }

        /**
         * @return The same array as an object.
         */
        @cache get object() {
            return new Object(this.handle);
        }

        /**
         * Creates a new array.
         * @param klass The class of the elements.
         * @param elements The elements.
         * @return A new array.
         */
        static from<T extends AllowedType>(klass: Class, elements: T[]) {
            const handle = Api._arrayNew(klass.handle, elements.length);
            const array = new Array<T>(handle);
            elements.forEach((e, i) => array.set(i, e));
            return array;
        }

        /**
         * @param index The index of the element. It must be between the array bounds.
         * @return The element at the given index.
         */
        get(index: number) {
            if (index < 0 || index >= this.length) {
                raise(`Array index '${index}' out of bounds (length: ${this.length}).`);
            }
            return readFieldValue(this.elements.add(index * this.elementSize), this.elementType) as T;
        }

        /**
         * @param index The index of the element. It must be between the array bounds.
         * @param v The value of the element.
         */
        set(index: number, v: T) {
            if (index < 0 || index >= this.length) {
                raise(`Array index '${index}' out of bounds (length: ${this.length}).`);
            }
            writeFieldValue(this.elements.add(index * this.elementSize), v, this.elementType);
        }

        /**
         * Iterable.
         */
        *[Symbol.iterator]() {
            for (let i = 0; i < this.length; i++) yield this.get(i);
        }
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
    export class Type {
        /** @internal */
        constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        /** @internal */
        @cache
        static get offsetOfTypeEnum() {
            return Api._typeOffsetOfTypeEnum();
        }

        /** @internal */
        @cache get aliasForFrida() {
            switch (this.typeEnum) {
                case TypeEnum.VOID:
                    return "void";
                case TypeEnum.BOOLEAN:
                    return "bool";
                case TypeEnum.CHAR:
                    return "char";
                case TypeEnum.I1:
                    return "int8";
                case TypeEnum.U1:
                    return "uint8";
                case TypeEnum.I2:
                    return "int16";
                case TypeEnum.U2:
                    return "uint16";
                case TypeEnum.I4:
                    return "int32";
                case TypeEnum.U4:
                    return "uint32";
                case TypeEnum.I8:
                    return "int64";
                case TypeEnum.U8:
                    return "uint64";
                case TypeEnum.R4:
                    return "float";
                case TypeEnum.R8:
                    return "double";
                default:
                    return "pointer";
            }
        }

        /**
         * @return Its class.
         */
        @cache get class() {
            return new Class(Api._classFromType(this.handle));
        }

        /**
         * @return If it's an array, the type of its elements, `null` otherwise.
         */
        @cache get dataType() {
            return getOrNull(Api._typeGetDataType(this.handle), Type);
        }

        /**
         * @returns If it's a generic type, its generic class, `null` otherwise.
         */
        @cache get genericClass() {
            return getOrNull(Api._typeGetGenericClass(this.handle), GenericClass);
        }

        /**
         *  @returns `true` if it's passed by reference, `false` otherwise.
         */
        @cache get isByReference() {
            return Api._typeIsByReference(this.handle);
        }

        /**
         * @returns Its name, namespace included and declaring class excluded. If its class is nested,
         * it corresponds to the class name.
         */
        @cache get name() {
            return Api._typeGetName(this.handle)!;
        }

        /**
         * @returns Its corresponding type.
         */
        @cache get typeEnum() {
            return Api._typeGetTypeEnum(this.handle) as TypeEnum;
        }
    }

    /**
     * Represents the enum `Il2CppTypeEnum`.
     */
    export enum TypeEnum {
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
     * Garbage collector utility functions.
     */
    export namespace GC {
        /**
         * Forces the GC to collect object from the given
         * [generation](https://docs.microsoft.com/en-us/dotnet/standard/garbage-collection/fundamentals#generations).
         * @param generation The category of objects to collect.
         */
        export function collect(generation: 0 | 1 | 2) {
            Api._gcCollect(generation);
        }

        /**
         * Like {@link Il2Cpp.GC.collect | collect}, but I don't know which
         * generation it collects.\
         * Available since Unity version `5.3.5`.
         */
        export function collectALittle() {
            if (unityVersion.isBelow_5_3_5) raise("Operation not available.");
            Api._gcCollectALittle();
        }

        /**
         * Disables the GC.\
         * Available since Unity version `5.3.5`.
         */
        export function disable() {
            if (unityVersion.isBelow_5_3_5) raise("Operation not available.");
            Api._gcDisable();
        }

        /**
         * Enables the GC.\
         * Available since Unity version `5.3.5`.
         */
        export function enable() {
            if (unityVersion.isBelow_5_3_5) raise("Operation not available.");
            Api._gcEnable();
        }

        /**
         * Available since Unity version `2018.3.0`.
         * @return `true` if the GC is disabled, `false` otherwise.
         */
        export function isDisabled() {
            if (unityVersion.isBelow_2018_3_0) raise("Operation not available.");
            return Api._gcIsDisabled();
        }
    }

    /**
     * Represents a `Il2CppMemorySnapshot`.
     * @internal
     */
    class MemorySnapshot {
        private isFreed = false;

        private constructor(readonly handle: NativePointer) {
            if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
        }

        @cache get trackedObjectCount() {
            return this.isFreed ? -1 : Api._memorySnapshotGetTrackedObjectCount(this.handle).toNumber();
        }

        @cache get objectsPointer() {
            return this.isFreed ? NULL : Api._memorySnapshotGetObjects(this.handle);
        }

        static capture() {
            return new MemorySnapshot(Api._memorySnapshotCapture());
        }

        free() {
            this.isFreed = true;
            Api._memorySnapshotFree(this.handle);
        }
    }

    /**
     * Types this module is familiar with.
     */
    export type AllowedType =
        | undefined
        | boolean
        | number
        | Int64
        | UInt64
        | NativePointer
        | ValueType
        | Object
        | String
        | Array<AllowedType>;

    /** @internal */
    function isCoherent(value: AllowedType, type: Type) {
        switch (type.typeEnum) {
            case TypeEnum.VOID:
                return value == undefined;
            case TypeEnum.BOOLEAN:
                return typeof value == "boolean";
            case TypeEnum.I1:
            case TypeEnum.U1:
            case TypeEnum.I2:
            case TypeEnum.U2:
            case TypeEnum.I4:
            case TypeEnum.U4:
            case TypeEnum.CHAR:
            case TypeEnum.R4:
            case TypeEnum.R8:
                return typeof value == "number";
            case TypeEnum.I8:
                return typeof value == "number" || value instanceof Int64;
            case TypeEnum.U8:
                return typeof value == "number" || value instanceof UInt64;
            case TypeEnum.I:
            case TypeEnum.U:
            case TypeEnum.PTR:
                return value instanceof NativePointer;
            case TypeEnum.VALUETYPE:
                if (type.class.isEnum) return typeof value == "number";
                return value instanceof ValueType;
            case TypeEnum.CLASS:
            case TypeEnum.GENERICINST:
            case TypeEnum.OBJECT:
                return value instanceof Object;
            case TypeEnum.STRING:
                return value instanceof String;
            case TypeEnum.SZARRAY:
                return value instanceof Array;
            default:
                raise(`isCoherent: case for "${type.name}" (${TypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`);
        }
    }

    /** @internal */
    function readFieldValue(pointer: NativePointer, type: Type): AllowedType {
        if (pointer.isNull()) {
            return undefined;
        }
        switch (type.typeEnum) {
            case TypeEnum.VOID:
                return undefined;
            case TypeEnum.BOOLEAN:
                return !!pointer.readS8();
            case TypeEnum.I1:
                return pointer.readS8();
            case TypeEnum.U1:
                return pointer.readU8();
            case TypeEnum.I2:
                return pointer.readS16();
            case TypeEnum.U2:
                return pointer.readU16();
            case TypeEnum.I4:
                return pointer.readS32();
            case TypeEnum.U4:
                return pointer.readU32();
            case TypeEnum.CHAR:
                return pointer.readU16();
            case TypeEnum.I8:
                return pointer.readS64();
            case TypeEnum.U8:
                return pointer.readU64();
            case TypeEnum.R4:
                return pointer.readFloat();
            case TypeEnum.R8:
                return pointer.readDouble();
            case TypeEnum.I:
            case TypeEnum.U:
            case TypeEnum.PTR:
                return pointer.readPointer();
            case TypeEnum.VALUETYPE:
                return type.class.isEnum ? pointer.readS32() : new ValueType(pointer, type.class);
            case TypeEnum.CLASS:
            case TypeEnum.GENERICINST:
            case TypeEnum.OBJECT:
                return new Object(pointer.readPointer());
            case TypeEnum.STRING:
                return new Il2Cpp.String(pointer.readPointer());
            case TypeEnum.SZARRAY:
                return new Array(pointer.readPointer());
            default:
                raise(
                    `readFieldValue: case for "${type.name}" (${TypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`
                );
        }
    }

    /** @internal */
    function writeFieldValue(pointer: NativePointer, value: AllowedType, type: Type) {
        if (!isCoherent(value, type)) {
            raise(`A "${type.name}" is required, but a "${JSObject.getPrototypeOf(value).constructor.name}" was supplied.`);
        }

        switch (type.typeEnum) {
            case TypeEnum.VOID:
                pointer.writePointer(NULL);
                break;
            case TypeEnum.BOOLEAN: {
                pointer.writeU8(+(value as boolean));
                break;
            }
            case TypeEnum.I1:
                pointer.writeS8(value as number);
                break;
            case TypeEnum.U1:
                pointer.writeU8(value as number);
                break;
            case TypeEnum.I2:
                pointer.writeS16(value as number);
                break;
            case TypeEnum.U2:
                pointer.writeU16(value as number);
                break;
            case TypeEnum.I4:
                pointer.writeS32(value as number);
                break;
            case TypeEnum.U4:
                pointer.writeU32(value as number);
                break;
            case TypeEnum.CHAR:
                pointer.writeU16(value as number);
                break;
            case TypeEnum.I8: {
                const v = value instanceof Int64 ? value.toNumber() : (value as number);
                pointer.writeS64(v);
                break;
            }
            case TypeEnum.U8: {
                const v = value instanceof UInt64 ? value.toNumber() : (value as number);
                pointer.writeS64(v);
                break;
            }
            case TypeEnum.R4:
                pointer.writeFloat(value as number);
                break;
            case TypeEnum.R8:
                pointer.writeDouble(value as number);
                break;
            case TypeEnum.I:
            case TypeEnum.U:
            case TypeEnum.PTR:
                pointer.writePointer(value as NativePointer);
                break;
            case TypeEnum.VALUETYPE:
                if (type.class.isEnum) pointer.writeS32(value as number);
                else pointer.writePointer((value as ValueType).handle);
                break;
            case TypeEnum.STRING:
                pointer.writePointer((value as String).handle);
                break;
            case TypeEnum.CLASS:
            case TypeEnum.OBJECT:
            case TypeEnum.GENERICINST:
                pointer.writePointer((value as Object).handle);
                break;
            case TypeEnum.SZARRAY:
                pointer.writePointer((value as Array<AllowedType>).handle);
                break;
            default:
                raise(
                    `writeFieldValue: case for "${type.name}" (${TypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`
                );
        }
    }

    /** @internal */
    function readRawValue(pointer: NativePointer, type: Type): AllowedType {
        if (pointer == undefined) {
            return;
        }
        switch (type.typeEnum) {
            case TypeEnum.VOID:
                return;
            case TypeEnum.BOOLEAN:
                return !!+pointer;
            case TypeEnum.I1:
                return +pointer;
            case TypeEnum.U1:
                return +pointer;
            case TypeEnum.I2:
                return +pointer;
            case TypeEnum.U2:
                return +pointer;
            case TypeEnum.I4:
                return +pointer;
            case TypeEnum.U4:
                return +pointer;
            case TypeEnum.CHAR:
                return +pointer;
            case TypeEnum.I8:
                return int64(pointer.toString());
            case TypeEnum.U8:
                return int64(pointer.toString());
            case TypeEnum.R4:
                return pointer.readFloat();
            case TypeEnum.R8:
                return pointer.readDouble();
            case TypeEnum.I:
            case TypeEnum.U:
            case TypeEnum.PTR:
                return pointer.isNull() ? NULL : pointer.readPointer();
            case TypeEnum.VALUETYPE:
                return type.class.isEnum ? +pointer : new ValueType(pointer, type.class);
            case TypeEnum.STRING:
                return pointer.isNull() ? undefined : new Il2Cpp.String(pointer);
            case TypeEnum.CLASS:
            case TypeEnum.GENERICINST:
            case TypeEnum.OBJECT:
                return new Object(pointer);
            case TypeEnum.SZARRAY:
                return new Array(pointer);
            default:
                raise(
                    `readRawValue: case for "${type.name}" (${TypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`
                );
        }
    }

    /** @internal */
    function allocRawValue(value: AllowedType, type: Type) {
        if (!isCoherent(value, type)) {
            raise(`A "${type.name}" is required, but a "${JSObject.getPrototypeOf(value).constructor.name}" was supplied.`);
        }

        switch (type.typeEnum) {
            case TypeEnum.VOID:
                return NULL;
            case TypeEnum.BOOLEAN:
                return ptr(+(value as boolean));
            case TypeEnum.I1:
                return ptr(value as number);
            case TypeEnum.U1:
                return ptr(value as number);
            case TypeEnum.I2:
                return ptr(value as number);
            case TypeEnum.U2:
                return ptr(value as number);
            case TypeEnum.I4:
                return ptr(value as number);
            case TypeEnum.U4:
                return ptr(value as number);
            case TypeEnum.CHAR:
                return ptr(value as number);
            case TypeEnum.I8: {
                const v = value instanceof Int64 ? value.toNumber() : (value as number);
                return ptr(v);
            }
            case TypeEnum.U8: {
                const v = value instanceof UInt64 ? value.toNumber() : (value as number);
                return ptr(v);
            }
            case TypeEnum.R4:
                return Memory.alloc(4).writeFloat(value as number);
            case TypeEnum.R8:
                return Memory.alloc(8).writeDouble(value as number);
            case TypeEnum.PTR:
            case TypeEnum.I:
            case TypeEnum.U:
                return value as NativePointer;
            case TypeEnum.VALUETYPE:
                return type.class.isEnum ? ptr(value as number) : (value as ValueType).handle;
            case TypeEnum.STRING:
                return (value as String).handle;
            case TypeEnum.CLASS:
            case TypeEnum.OBJECT:
            case TypeEnum.GENERICINST:
                return (value as Object).handle;
            case TypeEnum.SZARRAY:
                return (value as Array<AllowedType>).handle;
            default:
                raise(
                    `allocRawValue: case for "${type.name}" (${TypeEnum[type.typeEnum]}) has not been handled yet. Please file an issue!)`
                );
        }
    }
}

type Il2Cpp = typeof Il2Cpp;

declare global {
    const Il2Cpp: Il2Cpp;
}

(global as any).Il2Cpp = Il2Cpp;
