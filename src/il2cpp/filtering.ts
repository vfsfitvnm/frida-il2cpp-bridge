/** Filtering utilities. */
class Il2CppFiltering {
    protected constructor() {}

    /** Creates a filter which includes `element`s whose type can be assigned to `klass` variables. */
    static Is<T extends Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type>(klass: Il2Cpp.Class): (element: T) => boolean {
        return (element: T): boolean => {
            if (element instanceof Il2Cpp.Class) {
                return klass.isAssignableFrom(element);
            } else {
                return klass.isAssignableFrom(element.class);
            }
        };
    }

    /** Creates a filter which includes `element`s whose type corresponds to `klass` type. */
    static IsExactly<T extends Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type>(klass: Il2Cpp.Class): (element: T) => boolean {
        return (element: T): boolean => {
            if (element instanceof Il2Cpp.Class) {
                return element.equals(klass);
            } else {
                return element.class.equals(klass);
            }
        };
    }
}

Il2Cpp.Filtering = Il2CppFiltering;

declare global {
    namespace Il2Cpp {
        class Filtering extends Il2CppFiltering {}
    }
}

export {};
