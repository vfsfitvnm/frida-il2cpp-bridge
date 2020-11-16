import Il2CppAssembly from "./assembly";
import Api from "./api";
import { lazy } from "../utils/decorators";
import { Accessor } from "../utils/accessor";
import { raise } from "../utils/console";

/** @internal */
export default class Il2CppDomain {
    private static instance: Il2CppDomain;

    constructor(readonly handle: NativePointer) {
        if (handle.isNull()) raise(`Handle for "${this.constructor.name}" cannot be NULL.`);
    }

    @lazy get name() {
        return Api._domainGetName(this.handle);
    }

    @lazy get assemblies() {
        const accessor = new Accessor<Il2CppAssembly>();

        const sizePointer = Memory.alloc(Process.pointerSize);
        const startPointer = Api._domainGetAssemblies(NULL, sizePointer);

        if (startPointer.isNull()) {
            raise("First assembly pointer is NULL.");
        }

        const count = sizePointer.readInt();

        for (let i = 0; i < count; i++) {
            const assembly = new Il2CppAssembly(startPointer.add(i * Process.pointerSize).readPointer());
            accessor[assembly.name!] = assembly;
        }
        return accessor;
    }

    static async get() {
        if (this.instance == undefined) {
            const domainPointer = await new Promise<NativePointer>((resolve) => {
                const start = Api._domainGetAssemblies(NULL, Memory.alloc(Process.pointerSize));
                if (!start.isNull()) {
                    resolve(Api._domainGet());
                } else {
                    const interceptor = Interceptor.attach(Api._init, {
                        onLeave() {
                            setTimeout(() => interceptor.detach());
                            resolve(Api._domainGet());
                        },
                    });
                }
            });
            this.instance = new Il2CppDomain(domainPointer);
            Api._threadAttach(this.instance.handle);
        }
        return this.instance;
    }
}
