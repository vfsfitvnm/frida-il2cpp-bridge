namespace Il2Cpp {
    interface ParameterValue {
        type: Il2Cpp.Type;
        value: Il2Cpp.Parameter.Type;
    }

    function isParameterValue(v: ParameterValue | Il2Cpp.Parameter.Type): v is ParameterValue {
        return (v as ParameterValue).type !== undefined;
    }

    @recycle
    export class Class extends NativeStruct {
        /** Gets the actual size of the instance of the current class. */
        get actualInstanceSize(): number {
            const SystemString = Il2Cpp.corlib.class("System.String");

            // prettier-ignore
            const offset = SystemString.handle.offsetOf(_ => _.readInt() == SystemString.instanceSize - 2) 
                ?? raise("couldn't find the actual instance size offset in the native class struct");

            // prettier-ignore
            getter(Il2Cpp.Class.prototype, "actualInstanceSize", function (this: Il2Cpp.Class) {
                return this.handle.add(offset).readS32();
            }, lazy);

            return this.actualInstanceSize;
        }

        /** Gets the array class which encompass the current class. */
        @lazy
        get arrayClass(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.exports.classGetArrayClass(this, 1));
        }

        /** Gets the size of the object encompassed by the current array class. */
        @lazy
        get arrayElementSize(): number {
            return Il2Cpp.exports.classGetArrayElementSize(this);
        }

        /** Gets the name of the assembly in which the current class is defined. */
        @lazy
        get assemblyName(): string {
            return Il2Cpp.exports.classGetAssemblyName(this).readUtf8String()!.replace(".dll", "");
        }

        /** Gets the class that declares the current nested class. */
        @lazy
        get declaringClass(): Il2Cpp.Class | null {
            return new Il2Cpp.Class(Il2Cpp.exports.classGetDeclaringType(this)).asNullable();
        }

        /** Gets the encompassed type of this array, reference, pointer or enum type. */
        @lazy
        get baseType(): Il2Cpp.Type | null {
            return new Il2Cpp.Type(Il2Cpp.exports.classGetBaseType(this)).asNullable();
        }

        /** Gets the class of the object encompassed or referred to by the current array, pointer or reference class. */
        @lazy
        get elementClass(): Il2Cpp.Class | null {
            return new Il2Cpp.Class(Il2Cpp.exports.classGetElementClass(this)).asNullable();
        }

        /** Gets the fields of the current class. */
        @lazy
        get fields(): Il2Cpp.Field[] {
            return readNativeIterator(_ => Il2Cpp.exports.classGetFields(this, _)).map(_ => new Il2Cpp.Field(_));
        }

        /** Gets the flags of the current class. */
        @lazy
        get flags(): number {
            return Il2Cpp.exports.classGetFlags(this);
        }

        /** Gets the full name (namespace + name) of the current class. */
        @lazy
        get fullName(): string {
            return this.namespace ? `${this.namespace}.${this.name}` : this.name;
        }

        /** Gets the generics parameters of this generic class. */
        @lazy
        get generics(): Il2Cpp.Class[] {
            if (!this.isGeneric && !this.isInflated) {
                return [];
            }

            const types = this.type.object.method<Il2Cpp.Array<Il2Cpp.Object>>("GetGenericArguments").invoke();
            return globalThis.Array.from(types).map(_ => new Il2Cpp.Class(Il2Cpp.exports.classFromObject(_)));
        }

        /** Determines whether the GC has tracking references to the current class instances. */
        @lazy
        get hasReferences(): boolean {
            return !!Il2Cpp.exports.classHasReferences(this);
        }

        /** Determines whether ther current class has a valid static constructor. */
        @lazy
        get hasStaticConstructor(): boolean {
            const staticConstructor = this.tryMethod(".cctor");
            return staticConstructor != null && !staticConstructor.virtualAddress.isNull();
        }

        /** Gets the image in which the current class is defined. */
        @lazy
        get image(): Il2Cpp.Image {
            return new Il2Cpp.Image(Il2Cpp.exports.classGetImage(this));
        }

        /** Gets the size of the instance of the current class. */
        @lazy
        get instanceSize(): number {
            return Il2Cpp.exports.classGetInstanceSize(this);
        }

        /** Determines whether the current class is abstract. */
        @lazy
        get isAbstract(): boolean {
            return !!Il2Cpp.exports.classIsAbstract(this);
        }

        /** Determines whether the current class is blittable. */
        @lazy
        get isBlittable(): boolean {
            return !!Il2Cpp.exports.classIsBlittable(this);
        }

        /** Determines whether the current class is an enumeration. */
        @lazy
        get isEnum(): boolean {
            return !!Il2Cpp.exports.classIsEnum(this);
        }

        /** Determines whether the current class is a generic one. */
        @lazy
        get isGeneric(): boolean {
            return !!Il2Cpp.exports.classIsGeneric(this);
        }

        /** Determines whether the current class is inflated. */
        @lazy
        get isInflated(): boolean {
            return !!Il2Cpp.exports.classIsInflated(this);
        }

        /** Determines whether the current class is an interface. */
        @lazy
        get isInterface(): boolean {
            return !!Il2Cpp.exports.classIsInterface(this);
        }

        /** Determines whether the current class is a struct. */
        get isStruct(): boolean {
            return this.isValueType && !this.isEnum;
        }

        /** Determines whether the current class is a value type. */
        @lazy
        get isValueType(): boolean {
            return !!Il2Cpp.exports.classIsValueType(this);
        }

        /** Gets the interfaces implemented or inherited by the current class. */
        @lazy
        get interfaces(): Il2Cpp.Class[] {
            return readNativeIterator(_ => Il2Cpp.exports.classGetInterfaces(this, _)).map(_ => new Il2Cpp.Class(_));
        }

        /** Gets the methods implemented by the current class. */
        @lazy
        get methods(): Il2Cpp.Method[] {
            return readNativeIterator(_ => Il2Cpp.exports.classGetMethods(this, _)).map(_ => new Il2Cpp.Method(_));
        }

        /** Gets the name of the current class. */
        @lazy
        get name(): string {
            return Il2Cpp.exports.classGetName(this).readUtf8String()!;
        }

        /** Gets the namespace of the current class. */
        @lazy
        get namespace(): string {
            return Il2Cpp.exports.classGetNamespace(this).readUtf8String()!;
        }

        /** Gets the classes nested inside the current class. */
        @lazy
        get nestedClasses(): Il2Cpp.Class[] {
            return readNativeIterator(_ => Il2Cpp.exports.classGetNestedClasses(this, _)).map(_ => new Il2Cpp.Class(_));
        }

        /** Gets the class from which the current class directly inherits. */
        @lazy
        get parent(): Il2Cpp.Class | null {
            return new Il2Cpp.Class(Il2Cpp.exports.classGetParent(this)).asNullable();
        }

        /** Gets the rank (number of dimensions) of the current array class. */
        @lazy
        get rank(): number {
            let rank = 0;
            const name = this.name;

            for (let i = this.name.length - 1; i > 0; i--) {
                const c = name[i];

                if (c == "]") rank++;
                else if (c == "[" || rank == 0) break;
                else if (c == ",") rank++;
                else break;
            }

            return rank;
        }

        /** Gets a pointer to the static fields of the current class. */
        @lazy
        get staticFieldsData(): NativePointer {
            return Il2Cpp.exports.classGetStaticFieldData(this);
        }

        /** Gets the size of the instance - as a value type - of the current class. */
        @lazy
        get valueTypeSize(): number {
            return Il2Cpp.exports.classGetValueTypeSize(this, NULL);
        }

        /** Gets the type of the current class. */
        @lazy
        get type(): Il2Cpp.Type {
            return new Il2Cpp.Type(Il2Cpp.exports.classGetType(this));
        }

        /** Allocates a new object of the current class. */
        alloc(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.exports.objectNew(this));
        }

        /** Gets the field identified by the given name. */
        field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> {
            return this.tryField<T>(name) ?? raise(`couldn't find field ${name} in class ${this.type.name}`);
        }

        /** Builds a generic instance of the current generic class. */
        inflate(...classes: Il2Cpp.Class[]): Il2Cpp.Class {
            if (!this.isGeneric) {
                raise(`cannot inflate class ${this.type.name} as it has no generic parameters`);
            }

            if (this.generics.length != classes.length) {
                raise(`cannot inflate class ${this.type.name} as it needs ${this.generics.length} generic parameter(s), not ${classes.length}`);
            }

            const types = classes.map(_ => _.type.object);
            const typeArray = Il2Cpp.array(Il2Cpp.corlib.class("System.Type"), types);

            const inflatedType = this.type.object.method<Il2Cpp.Object>("MakeGenericType", 1).invoke(typeArray);
            return new Il2Cpp.Class(Il2Cpp.exports.classFromObject(inflatedType));
        }

        /** Calls the static constructor of the current class. */
        initialize(): Il2Cpp.Class {
            Il2Cpp.exports.classInitialize(this);
            return this;
        }

        /** Determines whether an instance of `other` class can be assigned to a variable of the current type. */
        isAssignableFrom(other: Il2Cpp.Class): boolean {
            return !!Il2Cpp.exports.classIsAssignableFrom(this, other);
        }

        /** Determines whether the current class derives from `other` class. */
        isSubclassOf(other: Il2Cpp.Class, checkInterfaces: boolean): boolean {
            return !!Il2Cpp.exports.classIsSubclassOf(this, other, +checkInterfaces);
        }

        /** Gets the method identified by the given name and parameter count. */
        method<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.Method<T> {
            return this.tryMethod<T>(name, parameterCount) ?? raise(`couldn't find method ${name} in class ${this.type.name}`);
        }

        methodWithSignature<T extends Il2Cpp.Method.ReturnType>(name: string, ...paramTypes: Il2Cpp.Type[]): Il2Cpp.Method<T> {
            return this.tryMethodWithSignature<T>(name, ...paramTypes) ?? raise(`couldn't find method ${name} in class ${this.type.name}`);
        }

        /** Gets the nested class with the given name. */
        nested(name: string): Il2Cpp.Class {
            return this.tryNested(name) ?? raise(`couldn't find nested class ${name} in class ${this.type.name}`);
        }

        /** Allocates a new object of the current class and calls its default constructor. */
        defaultNew(): Il2Cpp.Object {
            const object = this.alloc();

            const exceptionArray = Memory.alloc(Process.pointerSize);

            Il2Cpp.exports.objectInitialize(object, exceptionArray);

            const exception = exceptionArray.readPointer();

            if (!exception.isNull()) {
                raise(new Il2Cpp.Object(exception).toString());
            }

            return object;
        }

        /**
         * Finds the best fit constructor given the parameter types.
         * Doesn't cover constructors with default parameters – all parameters must be provided.
         */
        new(...parameters: (ParameterValue | Il2Cpp.Parameter.Type)[]): Il2Cpp.Object {
            if (parameters.length == 0) return this.defaultNew();

            const paramTypes = parameters.map(p => (isParameterValue(p) ? p.type : Il2Cpp.Type.fromValue(p)));
            const paramValues = parameters.map(p => (isParameterValue(p) ? p.value : p));

            const constructor =
                this.tryMethodWithSignature(".ctor", ...paramTypes) ?? raise(`Couldn't find constructor with signature ${paramTypes}) in class ${this.type})`);

            const object = this.alloc();
            constructor.withHolder(object).invoke(...paramValues);

            return object;
        }

        /** Gets the field with the given name. */
        tryField<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> | null {
            return new Il2Cpp.Field<T>(Il2Cpp.exports.classGetFieldFromName(this, Memory.allocUtf8String(name))).asNullable();
        }

        /** Gets the method with the given name and parameter count. */
        tryMethod<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.Method<T> | null {
            return new Il2Cpp.Method<T>(Il2Cpp.exports.classGetMethodFromName(this, Memory.allocUtf8String(name), parameterCount)).asNullable();
        }

        tryMethodWithSignature<T extends Il2Cpp.Method.ReturnType>(name: string, ...paramTypes: Il2Cpp.Type[]): Il2Cpp.Method<T> | undefined {
            return this.methods.find(
                m => m.name == name && m.parameters.length == paramTypes.length && m.parameters.every((p, i) => p.type.isSame(paramTypes[i]))
            ) as Il2Cpp.Method<T> | undefined;
        }

        /** Gets the nested class with the given name. */
        tryNested(name: string): Il2Cpp.Class | undefined {
            return this.nestedClasses.find(_ => _.name == name);
        }

        /** */
        toString(): string {
            const inherited = [this.parent].concat(this.interfaces);

            return `\
// ${this.assemblyName}
${this.isEnum ? `enum` : this.isStruct ? `struct` : this.isInterface ? `interface` : `class`} \
${this.type.name}\
${inherited ? ` : ${inherited.map(_ => _?.type.name).join(`, `)}` : ``}
{
    ${this.fields.join(`\n    `)}
    ${this.methods.join(`\n    `)}
}`;
        }

        /** Executes a callback for every defined class. */
        static enumerate(block: (klass: Il2Cpp.Class) => void): void {
            const callback = new NativeCallback(_ => block(new Il2Cpp.Class(_)), "void", ["pointer", "pointer"]);
            return Il2Cpp.exports.classForEach(callback, NULL);
        }
    }
}
