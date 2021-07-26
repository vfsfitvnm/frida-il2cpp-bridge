import { Api } from "../api";
import { injectToIl2Cpp } from "../decorators";

import { getOrNull } from "../../utils/native-struct";

@injectToIl2Cpp("GCHandle")
class Il2CppGCHandle {
    readonly weakRefId: WeakRefId;

    constructor(readonly handle: number) {
        this.weakRefId = Script.bindWeak(this, Api._gcHandleFree.bind(this, this.handle));
    }

    get target(): Il2Cpp.Object | null {
        return getOrNull(Api._gcHandleGetTarget(this.handle), Il2Cpp.Object);
    }

    free(): void {
        return Script.unbindWeak(this.weakRefId);
    }
}
