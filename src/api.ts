namespace Il2Cpp {
    /**
     * The **core** object where all the necessary IL2CPP native functions are
     * held. \
     * `frida-il2cpp-bridge` is built around this object by providing an
     * easy-to-use abstraction layer: the user isn't expected to use it directly,
     * but it can in case of advanced use cases.
     *
     * The APIs depends on the Unity version, hence some of them may be
     * unavailable; moreover, they are searched by **name** (e.g.
     * `il2cpp_class_from_name`) hence they might get stripped, hidden or
     * renamed by a nasty obfuscator.
     *
     * However, it is possible to override or set the handle of any of the
     * exports by using a global variable:
     * ```ts
     * declare global {
     *     let IL2CPP_EXPORTS: Record<string, () => NativePointer>;
     * }
     *
     * IL2CPP_EXPORTS = {
     *     il2cpp_image_get_class: () => Il2Cpp.module.base.add(0x1204c),
     *     il2cpp_class_get_parent: () => {
     *         return Memory.scanSync(Il2Cpp.module.base, Il2Cpp.module.size, "2f 10 ee 10 34 a8")[0].address;
     *     },
     * };
     *
     * Il2Cpp.perform(() => {
     *     // ...
     * });
     * ```
     */
    export const api = {
        get alloc() {
            return r("il2cpp_alloc", "pointer", ["size_t"]);
        },

        get arrayGetLength() {
            return r("il2cpp_array_length", "uint32", ["pointer"]);
        },

        get arrayNew() {
            return r("il2cpp_array_new", "pointer", ["pointer", "uint32"]);
        },

        get assemblyGetImage() {
            return r("il2cpp_assembly_get_image", "pointer", ["pointer"]);
        },

        get classForEach() {
            return r("il2cpp_class_for_each", "void", ["pointer", "pointer"]);
        },

        get classFromName() {
            return r("il2cpp_class_from_name", "pointer", ["pointer", "pointer", "pointer"]);
        },

        get classFromObject() {
            return r("il2cpp_class_from_system_type", "pointer", ["pointer"]);
        },

        get classGetArrayClass() {
            return r("il2cpp_array_class_get", "pointer", ["pointer", "uint32"]);
        },

        get classGetArrayElementSize() {
            return r("il2cpp_class_array_element_size", "int", ["pointer"]);
        },

        get classGetAssemblyName() {
            return r("il2cpp_class_get_assemblyname", "pointer", ["pointer"]);
        },

        get classGetBaseType() {
            return r("il2cpp_class_enum_basetype", "pointer", ["pointer"]);
        },

        get classGetDeclaringType() {
            return r("il2cpp_class_get_declaring_type", "pointer", ["pointer"]);
        },

        get classGetElementClass() {
            return r("il2cpp_class_get_element_class", "pointer", ["pointer"]);
        },

        get classGetFieldFromName() {
            return r("il2cpp_class_get_field_from_name", "pointer", ["pointer", "pointer"]);
        },

        get classGetFields() {
            return r("il2cpp_class_get_fields", "pointer", ["pointer", "pointer"]);
        },

        get classGetFlags() {
            return r("il2cpp_class_get_flags", "int", ["pointer"]);
        },

        get classGetImage() {
            return r("il2cpp_class_get_image", "pointer", ["pointer"]);
        },

        get classGetInstanceSize() {
            return r("il2cpp_class_instance_size", "int32", ["pointer"]);
        },

        get classGetInterfaces() {
            return r("il2cpp_class_get_interfaces", "pointer", ["pointer", "pointer"]);
        },

        get classGetMethodFromName() {
            return r("il2cpp_class_get_method_from_name", "pointer", ["pointer", "pointer", "int"]);
        },

        get classGetMethods() {
            return r("il2cpp_class_get_methods", "pointer", ["pointer", "pointer"]);
        },

        get classGetName() {
            return r("il2cpp_class_get_name", "pointer", ["pointer"]);
        },

        get classGetNamespace() {
            return r("il2cpp_class_get_namespace", "pointer", ["pointer"]);
        },

        get classGetNestedClasses() {
            return r("il2cpp_class_get_nested_types", "pointer", ["pointer", "pointer"]);
        },

        get classGetParent() {
            return r("il2cpp_class_get_parent", "pointer", ["pointer"]);
        },

        get classGetStaticFieldData() {
            return r("il2cpp_class_get_static_field_data", "pointer", ["pointer"]);
        },

        get classGetValueTypeSize() {
            return r("il2cpp_class_value_size", "int32", ["pointer", "pointer"]);
        },

        get classGetType() {
            return r("il2cpp_class_get_type", "pointer", ["pointer"]);
        },

        get classHasReferences() {
            return r("il2cpp_class_has_references", "bool", ["pointer"]);
        },

        get classInitialize() {
            return r("il2cpp_runtime_class_init", "void", ["pointer"]);
        },

        get classIsAbstract() {
            return r("il2cpp_class_is_abstract", "bool", ["pointer"]);
        },

        get classIsAssignableFrom() {
            return r("il2cpp_class_is_assignable_from", "bool", ["pointer", "pointer"]);
        },

        get classIsBlittable() {
            return r("il2cpp_class_is_blittable", "bool", ["pointer"]);
        },

        get classIsEnum() {
            return r("il2cpp_class_is_enum", "bool", ["pointer"]);
        },

        get classIsGeneric() {
            return r("il2cpp_class_is_generic", "bool", ["pointer"]);
        },

        get classIsInflated() {
            return r("il2cpp_class_is_inflated", "bool", ["pointer"]);
        },

        get classIsInterface() {
            return r("il2cpp_class_is_interface", "bool", ["pointer"]);
        },

        get classIsSubclassOf() {
            return r("il2cpp_class_is_subclass_of", "bool", ["pointer", "pointer", "bool"]);
        },

        get classIsValueType() {
            return r("il2cpp_class_is_valuetype", "bool", ["pointer"]);
        },

        get domainGetAssemblyFromName() {
            return r("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
        },

        get domainGet() {
            return r("il2cpp_domain_get", "pointer", []);
        },

        get domainGetAssemblies() {
            return r("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]);
        },

        get fieldGetClass() {
            return r("il2cpp_field_get_parent", "pointer", ["pointer"]);
        },

        get fieldGetFlags() {
            return r("il2cpp_field_get_flags", "int", ["pointer"]);
        },

        get fieldGetName() {
            return r("il2cpp_field_get_name", "pointer", ["pointer"]);
        },

        get fieldGetOffset() {
            return r("il2cpp_field_get_offset", "int32", ["pointer"]);
        },

        get fieldGetStaticValue() {
            return r("il2cpp_field_static_get_value", "void", ["pointer", "pointer"]);
        },

        get fieldGetType() {
            return r("il2cpp_field_get_type", "pointer", ["pointer"]);
        },

        get fieldSetStaticValue() {
            return r("il2cpp_field_static_set_value", "void", ["pointer", "pointer"]);
        },

        get free() {
            return r("il2cpp_free", "void", ["pointer"]);
        },

        get gcCollect() {
            return r("il2cpp_gc_collect", "void", ["int"]);
        },

        get gcCollectALittle() {
            return r("il2cpp_gc_collect_a_little", "void", []);
        },

        get gcDisable() {
            return r("il2cpp_gc_disable", "void", []);
        },

        get gcEnable() {
            return r("il2cpp_gc_enable", "void", []);
        },

        get gcGetHeapSize() {
            return r("il2cpp_gc_get_heap_size", "int64", []);
        },

        get gcGetMaxTimeSlice() {
            return r("il2cpp_gc_get_max_time_slice_ns", "int64", []);
        },

        get gcGetUsedSize() {
            return r("il2cpp_gc_get_used_size", "int64", []);
        },

        get gcHandleGetTarget() {
            return r("il2cpp_gchandle_get_target", "pointer", ["uint32"]);
        },

        get gcHandleFree() {
            return r("il2cpp_gchandle_free", "void", ["uint32"]);
        },

        get gcHandleNew() {
            return r("il2cpp_gchandle_new", "uint32", ["pointer", "bool"]);
        },

        get gcHandleNewWeakRef() {
            return r("il2cpp_gchandle_new_weakref", "uint32", ["pointer", "bool"]);
        },

        get gcIsDisabled() {
            return r("il2cpp_gc_is_disabled", "bool", []);
        },

        get gcIsIncremental() {
            return r("il2cpp_gc_is_incremental", "bool", []);
        },

        get gcSetMaxTimeSlice() {
            return r("il2cpp_gc_set_max_time_slice_ns", "void", ["int64"]);
        },

        get gcStartIncrementalCollection() {
            return r("il2cpp_gc_start_incremental_collection", "void", []);
        },

        get gcStartWorld() {
            return r("il2cpp_start_gc_world", "void", []);
        },

        get gcStopWorld() {
            return r("il2cpp_stop_gc_world", "void", []);
        },

        get getCorlib() {
            return r("il2cpp_get_corlib", "pointer", []);
        },

        get imageGetAssembly() {
            return r("il2cpp_image_get_assembly", "pointer", ["pointer"]);
        },

        get imageGetClass() {
            return r("il2cpp_image_get_class", "pointer", ["pointer", "uint"]);
        },

        get imageGetClassCount() {
            return r("il2cpp_image_get_class_count", "uint32", ["pointer"]);
        },

        get imageGetName() {
            return r("il2cpp_image_get_name", "pointer", ["pointer"]);
        },

        get initialize() {
            return r("il2cpp_init", "void", ["pointer"]);
        },

        get livenessAllocateStruct() {
            return r("il2cpp_unity_liveness_allocate_struct", "pointer", ["pointer", "int", "pointer", "pointer", "pointer"]);
        },

        get livenessCalculationBegin() {
            return r("il2cpp_unity_liveness_calculation_begin", "pointer", ["pointer", "int", "pointer", "pointer", "pointer", "pointer"]);
        },

        get livenessCalculationEnd() {
            return r("il2cpp_unity_liveness_calculation_end", "void", ["pointer"]);
        },

        get livenessCalculationFromStatics() {
            return r("il2cpp_unity_liveness_calculation_from_statics", "void", ["pointer"]);
        },

        get livenessFinalize() {
            return r("il2cpp_unity_liveness_finalize", "void", ["pointer"]);
        },

        get livenessFreeStruct() {
            return r("il2cpp_unity_liveness_free_struct", "void", ["pointer"]);
        },

        get memorySnapshotCapture() {
            return r("il2cpp_capture_memory_snapshot", "pointer", []);
        },

        get memorySnapshotFree() {
            return r("il2cpp_free_captured_memory_snapshot", "void", ["pointer"]);
        },

        get memorySnapshotGetClasses() {
            return r("il2cpp_memory_snapshot_get_classes", "pointer", ["pointer", "pointer"]);
        },

        get memorySnapshotGetObjects() {
            return r("il2cpp_memory_snapshot_get_objects", "pointer", ["pointer", "pointer"]);
        },

        get methodGetClass() {
            return r("il2cpp_method_get_class", "pointer", ["pointer"]);
        },

        get methodGetFlags() {
            return r("il2cpp_method_get_flags", "uint32", ["pointer", "pointer"]);
        },

        get methodGetName() {
            return r("il2cpp_method_get_name", "pointer", ["pointer"]);
        },

        get methodGetObject() {
            return r("il2cpp_method_get_object", "pointer", ["pointer", "pointer"]);
        },

        get methodGetParameterCount() {
            return r("il2cpp_method_get_param_count", "uint8", ["pointer"]);
        },

        get methodGetParameterName() {
            return r("il2cpp_method_get_param_name", "pointer", ["pointer", "uint32"]);
        },

        get methodGetParameters() {
            return r("il2cpp_method_get_parameters", "pointer", ["pointer", "pointer"]);
        },

        get methodGetParameterType() {
            return r("il2cpp_method_get_param", "pointer", ["pointer", "uint32"]);
        },

        get methodGetReturnType() {
            return r("il2cpp_method_get_return_type", "pointer", ["pointer"]);
        },

        get methodIsGeneric() {
            return r("il2cpp_method_is_generic", "bool", ["pointer"]);
        },

        get methodIsInflated() {
            return r("il2cpp_method_is_inflated", "bool", ["pointer"]);
        },

        get methodIsInstance() {
            return r("il2cpp_method_is_instance", "bool", ["pointer"]);
        },

        get monitorEnter() {
            return r("il2cpp_monitor_enter", "void", ["pointer"]);
        },

        get monitorExit() {
            return r("il2cpp_monitor_exit", "void", ["pointer"]);
        },

        get monitorPulse() {
            return r("il2cpp_monitor_pulse", "void", ["pointer"]);
        },

        get monitorPulseAll() {
            return r("il2cpp_monitor_pulse_all", "void", ["pointer"]);
        },

        get monitorTryEnter() {
            return r("il2cpp_monitor_try_enter", "bool", ["pointer", "uint32"]);
        },

        get monitorTryWait() {
            return r("il2cpp_monitor_try_wait", "bool", ["pointer", "uint32"]);
        },

        get monitorWait() {
            return r("il2cpp_monitor_wait", "void", ["pointer"]);
        },

        get objectGetClass() {
            return r("il2cpp_object_get_class", "pointer", ["pointer"]);
        },

        get objectGetVirtualMethod() {
            return r("il2cpp_object_get_virtual_method", "pointer", ["pointer", "pointer"]);
        },

        get objectInitialize() {
            return r("il2cpp_runtime_object_init_exception", "void", ["pointer", "pointer"]);
        },

        get objectNew() {
            return r("il2cpp_object_new", "pointer", ["pointer"]);
        },

        get objectGetSize() {
            return r("il2cpp_object_get_size", "uint32", ["pointer"]);
        },

        get objectUnbox() {
            return r("il2cpp_object_unbox", "pointer", ["pointer"]);
        },

        get resolveInternalCall() {
            return r("il2cpp_resolve_icall", "pointer", ["pointer"]);
        },

        get stringGetChars() {
            return r("il2cpp_string_chars", "pointer", ["pointer"]);
        },

        get stringGetLength() {
            return r("il2cpp_string_length", "int32", ["pointer"]);
        },

        get stringNew() {
            return r("il2cpp_string_new", "pointer", ["pointer"]);
        },

        get valueTypeBox() {
            return r("il2cpp_value_box", "pointer", ["pointer", "pointer"]);
        },

        get threadAttach() {
            return r("il2cpp_thread_attach", "pointer", ["pointer"]);
        },

        get threadDetach() {
            return r("il2cpp_thread_detach", "void", ["pointer"]);
        },

        get threadGetAttachedThreads() {
            return r("il2cpp_thread_get_all_attached_threads", "pointer", ["pointer"]);
        },

        get threadGetCurrent() {
            return r("il2cpp_thread_current", "pointer", []);
        },

        get threadIsVm() {
            return r("il2cpp_is_vm_thread", "bool", ["pointer"]);
        },

        get typeGetClass() {
            return r("il2cpp_class_from_type", "pointer", ["pointer"]);
        },

        get typeGetName() {
            return r("il2cpp_type_get_name", "pointer", ["pointer"]);
        },

        get typeGetObject() {
            return r("il2cpp_type_get_object", "pointer", ["pointer"]);
        },

        get typeGetTypeEnum() {
            return r("il2cpp_type_get_type", "int", ["pointer"]);
        }
    };

    decorate(api, lazy);

    /** @internal */
    export declare const memorySnapshotApi: CModule;
    getter(Il2Cpp, "memorySnapshotApi", () => new CModule($inline_file("cmodules/memory-snapshot.c")), lazy);

    function r<R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(exportName: string, retType: R, argTypes: A) {
        const handle = (globalThis as any).IL2CPP_EXPORTS?.[exportName]?.() ?? Il2Cpp.module.findExportByName(exportName) ?? memorySnapshotApi[exportName];

        return new NativeFunction(handle ?? raise(`couldn't resolve export ${exportName}`), retType, argTypes);
    }

    declare const $inline_file: typeof import("ts-transformer-inline-file").$INLINE_FILE;
}
