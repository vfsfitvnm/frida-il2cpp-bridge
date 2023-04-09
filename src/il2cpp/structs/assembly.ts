namespace Il2Cpp {
    @recycle
    export class Assembly extends NonNullNativeStruct {
        /** Gets the image of this assembly. */
        @lazy
        get image(): Il2Cpp.Image {
            return new Il2Cpp.Image(Il2Cpp.Api._assemblyGetImage(this));
        }

        /** Gets the name of this assembly. */
        @lazy
        get name(): string {
            return this.image.name.replace(".dll", "");
        }

        /** Gets the encompassing object of the current assembly. */
        @lazy
        get object(): Il2Cpp.Object {
            return Il2Cpp.Image.corlib.class("System.Reflection.Assembly").method<Il2Cpp.Object>("Load").invoke(Il2Cpp.String.from(this.name));
        }
    }
}
