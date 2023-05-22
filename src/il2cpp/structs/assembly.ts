namespace Il2Cpp {
    @recycle
    export class Assembly extends NativeStruct {
        /** Gets the image of this assembly. */
        get image(): Il2Cpp.Image {
            let get = function (this: Il2Cpp.Assembly) {
                return new Il2Cpp.Image(Il2Cpp.api.assemblyGetImage(this));
            };

            try {
                Il2Cpp.api.assemblyGetImage;
            } catch (_) {
                get = function (this: Il2Cpp.Assembly) {
                    // We need to get the System.Reflection.Module of the current assembly;
                    // System.Reflection.Assembly::GetModulesInternal, for some reason,
                    // throws a NullReferenceExceptionin Unity 5.3.8f1, so we must rely on
                    // System.Type::get_Module instead.
                    // Now we need to get any System.Type of this assembly.
                    // We cannot use System.Reflection.Assembly::GetTypes because it may
                    // return an empty array; hence we use System.Reflection.Assembly::GetType
                    // to retrieve <Module>, a class/type that seems to be always present
                    // (despite being excluded from System.Reflection.Assembly::GetTypes).
                    return new Il2Cpp.Image(
                        this.object
                            .method<Il2Cpp.Object>("GetType", 1)
                            .invoke(Il2Cpp.string("<Module>"))
                            .method<Il2Cpp.Object>("get_Module")
                            .invoke()
                            .field<NativePointer>("_impl").value
                    );
                };
            }

            getter(Il2Cpp.Assembly.prototype, "image", get, lazy);

            return this.image;
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
