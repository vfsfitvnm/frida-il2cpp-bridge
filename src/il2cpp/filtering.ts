import { injectToIl2Cpp } from "./decorators";

@injectToIl2Cpp("Filtering")
class Filtering<T> {
    static Is(klass: Il2Cpp.Class): (element: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type) => boolean {
        return (element: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type): boolean => {
            if (element instanceof Il2Cpp.Class) {
                return klass.isAssignableFrom(element);
            } else {
                return klass.isAssignableFrom(element.class);
            }
        };
    }

    static IsExactly(klass: Il2Cpp.Class): (element: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type) => boolean {
        return (element: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.Type): boolean => {
            if (element instanceof Il2Cpp.Class) {
                return element.handle.equals(klass.handle);
            } else {
                return element.class.handle.equals(klass.handle);
            }
        };
    }
}
