namespace Il2Cpp {
    export const api = {
        get alloc() {
            return r("il2cpp_alloc", "pointer", ["size_t"]);
        },

        get arrayGetElements() {
            return r("il2cpp_array_get_elements", "pointer", ["pointer"]);
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

        get classFromSystemType() {
            return r("il2cpp_class_from_system_type", "pointer", ["pointer"]);
        },

        get classFromType() {
            return r("il2cpp_class_from_type", "pointer", ["pointer"]);
        },

        get classGetActualInstanceSize() {
            return r("il2cpp_class_get_actual_instance_size", "int32", ["pointer"]);
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

        get classGetRank() {
            return r("il2cpp_class_get_rank", "int", ["pointer"]);
        },

        get classGetStaticFieldData() {
            return r("il2cpp_class_get_static_field_data", "pointer", ["pointer"]);
        },

        get classGetValueSize() {
            return r("il2cpp_class_value_size", "int32", ["pointer", "pointer"]);
        },

        get classGetType() {
            return r("il2cpp_class_get_type", "pointer", ["pointer"]);
        },

        get classHasReferences() {
            return r("il2cpp_class_has_references", "bool", ["pointer"]);
        },

        get classInit() {
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

        get domainAssemblyOpen() {
            return r("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
        },

        get domainGet() {
            return r("il2cpp_domain_get", "pointer", []);
        },

        get domainGetAssemblies() {
            return r("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]);
        },

        get domainGetObject() {
            return r("il2cpp_domain_get_object", "pointer", []);
        },

        get fieldGetModifier() {
            return r("il2cpp_field_get_modifier", "pointer", ["pointer"]);
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

        get fieldIsLiteral() {
            return r("il2cpp_field_is_literal", "bool", ["pointer"]);
        },

        get fieldIsStatic() {
            return r("il2cpp_field_is_static", "bool", ["pointer"]);
        },

        get fieldIsThreadStatic() {
            return r("il2cpp_field_is_thread_static", "bool", ["pointer"]);
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

        get init() {
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

        get methodGetModifier() {
            return r("il2cpp_method_get_modifier", "pointer", ["pointer"]);
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

        get methodGetPointer() {
            return r("il2cpp_method_get_pointer", "pointer", ["pointer"]);
        },

        get methodGetReturnType() {
            return r("il2cpp_method_get_return_type", "pointer", ["pointer"]);
        },

        get methodIsExternal() {
            return r("il2cpp_method_is_external", "bool", ["pointer"]);
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

        get methodIsSynchronized() {
            return r("il2cpp_method_is_synchronized", "bool", ["pointer"]);
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

        get objectInit() {
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

        get stringChars() {
            return r("il2cpp_string_chars", "pointer", ["pointer"]);
        },

        get stringLength() {
            return r("il2cpp_string_length", "int32", ["pointer"]);
        },

        get stringNew() {
            return r("il2cpp_string_new", "pointer", ["pointer"]);
        },

        get stringSetLength() {
            return r("il2cpp_string_set_length", "void", ["pointer", "int32"]);
        },

        get valueBox() {
            return r("il2cpp_value_box", "pointer", ["pointer", "pointer"]);
        },

        get threadAttach() {
            return r("il2cpp_thread_attach", "pointer", ["pointer"]);
        },

        get threadCurrent() {
            return r("il2cpp_thread_current", "pointer", []);
        },

        get threadGetAllAttachedThreads() {
            return r("il2cpp_thread_get_all_attached_threads", "pointer", ["pointer"]);
        },

        get threadIsVm() {
            return r("il2cpp_is_vm_thread", "bool", ["pointer"]);
        },

        get threadDetach() {
            return r("il2cpp_thread_detach", "void", ["pointer"]);
        },

        get typeGetName() {
            return r("il2cpp_type_get_name", "pointer", ["pointer"]);
        },

        get typeGetObject() {
            return r("il2cpp_type_get_object", "pointer", ["pointer"]);
        },

        get typeGetTypeEnum() {
            return r("il2cpp_type_get_type", "int", ["pointer"]);
        },

        get typeIsByReference() {
            return r("il2cpp_type_is_byref", "bool", ["pointer"]);
        },

        get typeIsPrimitive() {
            return r("il2cpp_type_is_primitive", "bool", ["pointer"]);
        }
    };

    decorate(api, lazy);

    let cModule: Record<string, NativePointer | null> | null = null;

    function buildCModule(): Record<string, NativePointer | null> {
        const offsetsFinderCModule = new CModule($inline_file("cmodules/offset-of.c"));

        const offsetOfInt32 = new NativeFunction(offsetsFinderCModule.offset_of_int32, "int16", ["pointer", "int32"]);
        const offsetOfPointer = new NativeFunction(offsetsFinderCModule.offset_of_pointer, "int16", ["pointer", "pointer"]);

        const SystemString = Il2Cpp.corlib.class("System.String");
        const SystemDateTime = Il2Cpp.corlib.class("System.DateTime");
        const SystemReflectionModule = Il2Cpp.corlib.class("System.Reflection.Module");

        SystemDateTime.initialize();
        SystemReflectionModule.initialize();

        const DaysToMonth365 =
            SystemDateTime.tryField<Il2Cpp.Array<number>>("daysmonth")?.value ??
            SystemDateTime.tryField<Il2Cpp.Array<number>>("DaysToMonth365")?.value ??
            SystemDateTime.field<Il2Cpp.Array<number>>("s_daysToMonth365")?.value;

        const FilterTypeName = SystemReflectionModule.field<Il2Cpp.Object>("FilterTypeName").value;
        const FilterTypeNameMethodPointer = FilterTypeName.field<NativePointer>("method_ptr").value;
        const FilterTypeNameMethod = FilterTypeName.field<NativePointer>("method").value;

        const defines = `
            #define IL2CPP_STRING_SET_LENGTH_OFFSET ${offsetOfInt32(Il2Cpp.string("vfsfitvnm"), 9)}
            #define IL2CPP_ARRAY_GET_ELEMENTS_OFFSET ${offsetOfInt32(DaysToMonth365, 31) - 1}
            #define IL2CPP_CLASS_GET_ACTUAL_INSTANCE_SIZE_OFFSET ${offsetOfInt32(SystemString, SystemString.instanceSize - 2)}
            #define IL2CPP_METHOD_GET_POINTER_OFFSET ${offsetOfPointer(FilterTypeNameMethod, FilterTypeNameMethodPointer)}
        `;

        offsetsFinderCModule.dispose();

        const cModule = new CModule(defines + $inline_file("cmodules/api.c") + $inline_file("cmodules/memory-snapshot.c"), {
            il2cpp_class_from_name: api.classFromName,
            il2cpp_class_get_method_from_name: api.classGetMethodFromName,
            il2cpp_class_get_name: api.classGetName,
            il2cpp_field_get_flags: api.fieldGetFlags,
            il2cpp_field_get_offset: api.fieldGetOffset,
            il2cpp_free: api.free,
            il2cpp_image_get_corlib: api.getCorlib,
            il2cpp_method_get_flags: api.methodGetFlags,
            il2cpp_type_get_name: api.typeGetName,
            il2cpp_type_get_type_enum: api.typeGetTypeEnum
        });

        return cModule;
    }

    function r<R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(exportName: string, retType: R, argTypes: A) {
        const handle = Il2Cpp.module.findExportByName(exportName) ?? (cModule ??= buildCModule())[exportName];

        return new NativeFunction(handle ?? raise(`couldn't resolve export ${exportName}`), retType, argTypes);
    }

    declare const $inline_file: typeof import("ts-transformer-inline-file").$INLINE_FILE;
}
