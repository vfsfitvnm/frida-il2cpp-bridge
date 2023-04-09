namespace Il2Cpp {
    /** Creates a filter which includes `element`s whose type can be assigned to `klass` variables. */
    export function is<T extends Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type>(klass: Il2Cpp.Class): (element: T) => boolean {
        return (element: T): boolean => {
            if (element instanceof Il2Cpp.Class) {
                return klass.isAssignableFrom(element);
            } else {
                return klass.isAssignableFrom(element.class);
            }
        };
    }

    /** Creates a filter which includes `element`s whose type corresponds to `klass` type. */
    export function isExactly<T extends Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type>(klass: Il2Cpp.Class): (element: T) => boolean {
        return (element: T): boolean => {
            if (element instanceof Il2Cpp.Class) {
                return element.equals(klass);
            } else {
                return element.class.equals(klass);
            }
        };
    }
}
