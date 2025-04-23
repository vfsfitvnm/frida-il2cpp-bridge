namespace Il2Cpp {
    /**
     * Set of configurations users can override. It is for advanced use cases,
     * when certain values cannot be detected automatically. \
     * For reference, see:
     * - {@link Il2Cpp.module};
     * - {@link Il2Cpp.unityVersion};
     * - {@link Il2Cpp.exports};
     */
    export const $config: {
        moduleName?: string;
        unityVersion?: string;
        exports?: Record<`il2cpp_${string}`, () => NativePointer>;
    } = {
        moduleName: undefined,
        unityVersion: undefined,
        exports: undefined
    };
}
