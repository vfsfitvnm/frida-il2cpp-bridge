namespace Il2Cpp {
    @recycle
    export class Class extends NonNullNativeStruct {
        /** Gets the actual size of the instance of the current class. */
        @lazy
        get actualInstanceSize(): number {
            return Il2Cpp.Api._classGetActualInstanceSize(this);
        }

        /** Gets the array class which encompass the current class. */
        @lazy
        get arrayClass(): Il2Cpp.Class {
            return new Il2Cpp.Class(Il2Cpp.Api._classGetArrayClass(this, 1));
        }

        /** Gets the size of the object encompassed by the current array class. */
        @lazy
        get arrayElementSize(): number {
            return Il2Cpp.Api._classGetArrayElementSize(this);
        }

        /** Gets the name of the assembly in which the current class is defined. */
        @lazy
        get assemblyName(): string {
            return Il2Cpp.Api._classGetAssemblyName(this).readUtf8String()!;
        }

        /** Gets the class that declares the current nested class. */
        @lazy
        get declaringClass(): Il2Cpp.Class | null {
            const handle = Il2Cpp.Api._classGetDeclaringType(this);
            return handle.isNull() ? null : new Il2Cpp.Class(handle);
        }

        /** Gets the encompassed type of this array, reference, pointer or enum type. */
        @lazy
        get baseType(): Il2Cpp.Type | null {
            const handle = Il2Cpp.Api._classGetBaseType(this);
            return handle.isNull() ? null : new Il2Cpp.Type(handle);
        }

        /** Gets the class of the object encompassed or referred to by the current array, pointer or reference class. */
        @lazy
        get elementClass(): Il2Cpp.Class | null {
            const handle = Il2Cpp.Api._classGetElementClass(this);
            return handle.isNull() ? null : new Il2Cpp.Class(handle);
        }

        /** Gets the fields of the current class. */
        @lazy
        get fields(): Il2Cpp.Field[] {
            return readNativeIterator(_ => Il2Cpp.Api._classGetFields(this, _)).map(_ => new Il2Cpp.Field(_));
        }

        /** Gets the flags of the current class. */
        @lazy
        get flags(): number {
            return Il2Cpp.Api._classGetFlags(this);
        }

        /** Gets the full name (namespace + name) of the current class. */
        @lazy
        get fullName(): string {
            return this.namespace ? `${this.namespace}.${this.name}` : this.name;
        }

        /** Gets the amount of generic parameters of this generic class. */
        @lazy
        get genericParameterCount(): number {
            if (!this.isGeneric) {
                return 0;
            }

            return this.type.object.method<Il2Cpp.Array>("GetGenericArguments").invoke().length;
        }

        /** Determines whether the GC has tracking references to the current class instances. */
        @lazy
        get hasReferences(): boolean {
            return !!Il2Cpp.Api._classHasReferences(this);
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
            return new Il2Cpp.Image(Il2Cpp.Api._classGetImage(this));
        }

        /** Gets the size of the instance of the current class. */
        @lazy
        get instanceSize(): number {
            return Il2Cpp.Api._classGetInstanceSize(this);
        }

        /** Determines whether the current class is abstract. */
        @lazy
        get isAbstract(): boolean {
            return !!Il2Cpp.Api._classIsAbstract(this);
        }

        /** Determines whether the current class is blittable. */
        @lazy
        get isBlittable(): boolean {
            return !!Il2Cpp.Api._classIsBlittable(this);
        }

        /** Determines whether the current class is an enumeration. */
        @lazy
        get isEnum(): boolean {
            return !!Il2Cpp.Api._classIsEnum(this);
        }

        /** Determines whether the current class is a generic one. */
        @lazy
        get isGeneric(): boolean {
            return !!Il2Cpp.Api._classIsGeneric(this);
        }

        /** Determines whether the current class is inflated. */
        @lazy
        get isInflated(): boolean {
            return !!Il2Cpp.Api._classIsInflated(this);
        }

        /** Determines whether the current class is an interface. */
        @lazy
        get isInterface(): boolean {
            return !!Il2Cpp.Api._classIsInterface(this);
        }

        /** Determines whether the current class is a value type. */
        @lazy
        get isValueType(): boolean {
            return !!Il2Cpp.Api._classIsValueType(this);
        }

        /** Gets the interfaces implemented or inherited by the current class. */
        @lazy
        get interfaces(): Il2Cpp.Class[] {
            return readNativeIterator(_ => Il2Cpp.Api._classGetInterfaces(this, _)).map(_ => new Il2Cpp.Class(_));
        }

        /** Gets the methods implemented by the current class. */
        @lazy
        get methods(): Il2Cpp.Method[] {
            return readNativeIterator(_ => Il2Cpp.Api._classGetMethods(this, _)).map(_ => new Il2Cpp.Method(_));
        }

        /** Gets the name of the current class. */
        @lazy
        get name(): string {
            return Il2Cpp.Api._classGetName(this).readUtf8String()!;
        }

        /** Gets the namespace of the current class. */
        @lazy
        get namespace(): string {
            return Il2Cpp.Api._classGetNamespace(this).readUtf8String()!;
        }

        /** Gets the classes nested inside the current class. */
        @lazy
        get nestedClasses(): Il2Cpp.Class[] {
            return readNativeIterator(_ => Il2Cpp.Api._classGetNestedClasses(this, _)).map(_ => new Il2Cpp.Class(_));
        }

        /** Gets the class from which the current class directly inherits. */
        @lazy
        get parent(): Il2Cpp.Class | null {
            const handle = Il2Cpp.Api._classGetParent(this);
            return handle.isNull() ? null : new Il2Cpp.Class(handle);
        }

        /** Gets the rank (number of dimensions) of the current array class. */
        @lazy
        get rank(): number {
            return Il2Cpp.Api._classGetRank(this);
        }

        /** Gets a pointer to the static fields of the current class. */
        @lazy
        get staticFieldsData(): NativePointer {
            return Il2Cpp.Api._classGetStaticFieldData(this);
        }

        /** Gets the size of the instance - as a value type - of the current class. */
        @lazy
        get valueSize(): number {
            return Il2Cpp.Api._classGetValueSize(this, NULL);
        }

        /** Gets the type of the current class. */
        @lazy
        get type(): Il2Cpp.Type {
            return new Il2Cpp.Type(Il2Cpp.Api._classGetType(this));
        }

        /** Allocates a new object of the current class. */
        alloc(): Il2Cpp.Object {
            return new Il2Cpp.Object(Il2Cpp.Api._objectNew(this));
        }

        /** Gets the field identified by the given name. */
        field<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> {
            // prettier-ignore
            return this.tryField<T>(name) ?? keyNotFound(name, this.name, this.fields.map(_ => _.name));
        }

        /** Builds a generic instance of the current generic class. */
        inflate(...classes: Il2Cpp.Class[]): Il2Cpp.Class {
            if (!this.isGeneric) {
                raise(`cannot inflate class ${this.type.name}: it has no generic parameters`);
            }

            if (this.genericParameterCount != classes.length) {
                raise(`cannot inflate class ${this.type.name}: it needs ${this.genericParameterCount} generic parameter(s), not ${classes.length}`);
            }

            const types = classes.map(_ => _.type.object);
            const typeArray = Il2Cpp.Array.from(Il2Cpp.Image.corlib.class("System.Type"), types);

            const inflatedType = this.type.object.method<Il2Cpp.Object>("MakeGenericType", 1).invoke(typeArray);
            return new Il2Cpp.Class(Il2Cpp.Api._classFromSystemType(inflatedType));
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

        /** Gets the method identified by the given name and parameter count. */
        method<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.Method<T> {
            // prettier-ignore
            return this.tryMethod<T>(name, parameterCount) ?? keyNotFound(name, this.name, this.methods.map(_ => _.name));
        }

        /** Gets the nested class with the given name. */
        nested(name: string): Il2Cpp.Class {
            // prettier-ignore
            return this.tryNested(name) ?? keyNotFound(name, this.name, this.nestedClasses.map(_ => _.name));
        }

        /** Allocates a new object of the current class and calls its default constructor. */
        new(): Il2Cpp.Object {
            const object = this.alloc();

            const exceptionArray = Memory.alloc(Process.pointerSize);

            Il2Cpp.Api._objectInit(object, exceptionArray);

            const exception = exceptionArray.readPointer();

            if (!exception.isNull()) {
                raise(new Il2Cpp.Object(exception).toString());
            }

            return object;
        }

        /** Gets the field with the given name. */
        tryField<T extends Il2Cpp.Field.Type>(name: string): Il2Cpp.Field<T> | null {
            const handle = Il2Cpp.Api._classGetFieldFromName(this, Memory.allocUtf8String(name));
            return handle.isNull() ? null : new Il2Cpp.Field<T>(handle);
        }

        /** Gets the method with the given name and parameter count. */
        tryMethod<T extends Il2Cpp.Method.ReturnType>(name: string, parameterCount: number = -1): Il2Cpp.Method<T> | null {
            const handle = Il2Cpp.Api._classGetMethodFromName(this, Memory.allocUtf8String(name), parameterCount);
            return handle.isNull() ? null : new Il2Cpp.Method<T>(handle);
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
${this.isEnum ? `enum` : this.isValueType ? `struct` : this.isInterface ? `interface` : `class`} \
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
            return Il2Cpp.Api._classForEach(callback, NULL);
        }
    }
}
