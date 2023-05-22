namespace Il2Cpp {
    @recycle
    export class Assembly extends NativeStruct {
        /** Gets the image of this assembly. */
        @lazy
        get image(): Il2Cpp.Image {
            return new Il2Cpp.Image(Il2Cpp.api.assemblyGetImage(this));
        }

        /** Gets the name of this assembly. */
        @lazy
        get name(): string {
            return this.image.name.replace(".dll", "");
        }

        /** Gets the encompassing object of the current assembly. */
        @lazy
        get object(): Il2Cpp.Object {
            for (const _ of Il2Cpp.domain.object.method<Il2Cpp.Array<Il2Cpp.Object>>("GetAssemblies", 1).invoke(false)) {
                if (_.field<NativePointer>("_mono_assembly").value.equals(this)) {
                    return _;
                }
            }

            raise("couldn't find the object of the native assembly struct");
        }
    }
}
