namespace Il2Cpp {
    export class Api {
        protected constructor() {}

        @lazy
        static get alloc() {
            return this.r("il2cpp_alloc", "pointer", ["size_t"]);
        }

        @lazy
        static get arrayGetElements() {
            return this.r("il2cpp_array_get_elements", "pointer", ["pointer"]);
        }

        @lazy
        static get arrayGetLength() {
            return this.r("il2cpp_array_length", "uint32", ["pointer"]);
        }

        @lazy
        static get arrayNew() {
            return this.r("il2cpp_array_new", "pointer", ["pointer", "uint32"]);
        }

        @lazy
        static get assemblyGetImage() {
            return this.r("il2cpp_assembly_get_image", "pointer", ["pointer"]);
        }

        @lazy
        static get classForEach() {
            return this.r("il2cpp_class_for_each", "void", ["pointer", "pointer"]);
        }

        @lazy
        static get classFromName() {
            return this.r("il2cpp_class_from_name", "pointer", ["pointer", "pointer", "pointer"]);
        }

        @lazy
        static get classFromSystemType() {
            return this.r("il2cpp_class_from_system_type", "pointer", ["pointer"]);
        }

        @lazy
        static get classFromType() {
            return this.r("il2cpp_class_from_type", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetActualInstanceSize() {
            return this.r("il2cpp_class_get_actual_instance_size", "int32", ["pointer"]);
        }

        @lazy
        static get classGetArrayClass() {
            return this.r("il2cpp_array_class_get", "pointer", ["pointer", "uint32"]);
        }

        @lazy
        static get classGetArrayElementSize() {
            return this.r("il2cpp_class_array_element_size", "int", ["pointer"]);
        }

        @lazy
        static get classGetAssemblyName() {
            return this.r("il2cpp_class_get_assemblyname", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetBaseType() {
            return this.r("il2cpp_class_enum_basetype", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetDeclaringType() {
            return this.r("il2cpp_class_get_declaring_type", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetElementClass() {
            return this.r("il2cpp_class_get_element_class", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetFieldFromName() {
            return this.r("il2cpp_class_get_field_from_name", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get classGetFields() {
            return this.r("il2cpp_class_get_fields", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get classGetFlags() {
            return this.r("il2cpp_class_get_flags", "int", ["pointer"]);
        }

        @lazy
        static get classGetImage() {
            return this.r("il2cpp_class_get_image", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetInstanceSize() {
            return this.r("il2cpp_class_instance_size", "int32", ["pointer"]);
        }

        @lazy
        static get classGetInterfaces() {
            return this.r("il2cpp_class_get_interfaces", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get classGetMethodFromName() {
            return this.r("il2cpp_class_get_method_from_name", "pointer", ["pointer", "pointer", "int"]);
        }

        @lazy
        static get classGetMethods() {
            return this.r("il2cpp_class_get_methods", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get classGetName() {
            return this.r("il2cpp_class_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetNamespace() {
            return this.r("il2cpp_class_get_namespace", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetNestedClasses() {
            return this.r("il2cpp_class_get_nested_types", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get classGetParent() {
            return this.r("il2cpp_class_get_parent", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetRank() {
            return this.r("il2cpp_class_get_rank", "int", ["pointer"]);
        }

        @lazy
        static get classGetStaticFieldData() {
            return this.r("il2cpp_class_get_static_field_data", "pointer", ["pointer"]);
        }

        @lazy
        static get classGetValueSize() {
            return this.r("il2cpp_class_value_size", "int32", ["pointer", "pointer"]);
        }

        @lazy
        static get classGetType() {
            return this.r("il2cpp_class_get_type", "pointer", ["pointer"]);
        }

        @lazy
        static get classHasReferences() {
            return this.r("il2cpp_class_has_references", "bool", ["pointer"]);
        }

        @lazy
        static get classInit() {
            return this.r("il2cpp_runtime_class_init", "void", ["pointer"]);
        }

        @lazy
        static get classIsAbstract() {
            return this.r("il2cpp_class_is_abstract", "bool", ["pointer"]);
        }

        @lazy
        static get classIsAssignableFrom() {
            return this.r("il2cpp_class_is_assignable_from", "bool", ["pointer", "pointer"]);
        }

        @lazy
        static get classIsBlittable() {
            return this.r("il2cpp_class_is_blittable", "bool", ["pointer"]);
        }

        @lazy
        static get classIsEnum() {
            return this.r("il2cpp_class_is_enum", "bool", ["pointer"]);
        }

        @lazy
        static get classIsGeneric() {
            return this.r("il2cpp_class_is_generic", "bool", ["pointer"]);
        }

        @lazy
        static get classIsInflated() {
            return this.r("il2cpp_class_is_inflated", "bool", ["pointer"]);
        }

        @lazy
        static get classIsInterface() {
            return this.r("il2cpp_class_is_interface", "bool", ["pointer"]);
        }

        @lazy
        static get classIsSubclassOf() {
            return this.r("il2cpp_class_is_subclass_of", "bool", ["pointer", "pointer", "bool"]);
        }

        @lazy
        static get classIsValueType() {
            return this.r("il2cpp_class_is_valuetype", "bool", ["pointer"]);
        }

        @lazy
        static get domainAssemblyOpen() {
            return this.r("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get domainGet() {
            return this.r("il2cpp_domain_get", "pointer", []);
        }

        @lazy
        static get domainGetAssemblies() {
            return this.r("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get domainGetObject() {
            return this.r("il2cpp_domain_get_object", "pointer", []);
        }

        @lazy
        static get fieldGetModifier() {
            return this.r("il2cpp_field_get_modifier", "pointer", ["pointer"]);
        }

        @lazy
        static get fieldGetClass() {
            return this.r("il2cpp_field_get_parent", "pointer", ["pointer"]);
        }

        @lazy
        static get fieldGetFlags() {
            return this.r("il2cpp_field_get_flags", "int", ["pointer"]);
        }

        @lazy
        static get fieldGetName() {
            return this.r("il2cpp_field_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get fieldGetOffset() {
            return this.r("il2cpp_field_get_offset", "int32", ["pointer"]);
        }

        @lazy
        static get fieldGetStaticValue() {
            return this.r("il2cpp_field_static_get_value", "void", ["pointer", "pointer"]);
        }

        @lazy
        static get fieldGetType() {
            return this.r("il2cpp_field_get_type", "pointer", ["pointer"]);
        }

        @lazy
        static get fieldIsLiteral() {
            return this.r("il2cpp_field_is_literal", "bool", ["pointer"]);
        }

        @lazy
        static get fieldIsStatic() {
            return this.r("il2cpp_field_is_static", "bool", ["pointer"]);
        }

        @lazy
        static get fieldIsThreadStatic() {
            return this.r("il2cpp_field_is_thread_static", "bool", ["pointer"]);
        }

        @lazy
        static get fieldSetStaticValue() {
            return this.r("il2cpp_field_static_set_value", "void", ["pointer", "pointer"]);
        }

        @lazy
        static get free() {
            return this.r("il2cpp_free", "void", ["pointer"]);
        }

        @lazy
        static get gcCollect() {
            return this.r("il2cpp_gc_collect", "void", ["int"]);
        }

        @lazy
        static get gcCollectALittle() {
            return this.r("il2cpp_gc_collect_a_little", "void", []);
        }

        @lazy
        static get gcDisable() {
            return this.r("il2cpp_gc_disable", "void", []);
        }

        @lazy
        static get gcEnable() {
            return this.r("il2cpp_gc_enable", "void", []);
        }

        @lazy
        static get gcGetHeapSize() {
            return this.r("il2cpp_gc_get_heap_size", "int64", []);
        }

        @lazy
        static get gcGetMaxTimeSlice() {
            return this.r("il2cpp_gc_get_max_time_slice_ns", "int64", []);
        }

        @lazy
        static get gcGetUsedSize() {
            return this.r("il2cpp_gc_get_used_size", "int64", []);
        }

        @lazy
        static get gcHandleGetTarget() {
            return this.r("il2cpp_gchandle_get_target", "pointer", ["uint32"]);
        }

        @lazy
        static get gcHandleFree() {
            return this.r("il2cpp_gchandle_free", "void", ["uint32"]);
        }

        @lazy
        static get gcHandleNew() {
            return this.r("il2cpp_gchandle_new", "uint32", ["pointer", "bool"]);
        }

        @lazy
        static get gcHandleNewWeakRef() {
            return this.r("il2cpp_gchandle_new_weakref", "uint32", ["pointer", "bool"]);
        }

        @lazy
        static get gcIsDisabled() {
            return this.r("il2cpp_gc_is_disabled", "bool", []);
        }

        @lazy
        static get gcIsIncremental() {
            return this.r("il2cpp_gc_is_incremental", "bool", []);
        }

        @lazy
        static get gcSetMaxTimeSlice() {
            return this.r("il2cpp_gc_set_max_time_slice_ns", "void", ["int64"]);
        }

        @lazy
        static get gcStartIncrementalCollection() {
            return this.r("il2cpp_gc_start_incremental_collection", "void", []);
        }

        @lazy
        static get gcStartWorld() {
            return this.r("il2cpp_start_gc_world", "void", []);
        }

        @lazy
        static get gcStopWorld() {
            return this.r("il2cpp_stop_gc_world", "void", []);
        }

        @lazy
        static get getCorlib() {
            return this.r("il2cpp_get_corlib", "pointer", []);
        }

        @lazy
        static get imageGetAssembly() {
            return this.r("il2cpp_image_get_assembly", "pointer", ["pointer"]);
        }

        @lazy
        static get imageGetClass() {
            return this.r("il2cpp_image_get_class", "pointer", ["pointer", "uint"]);
        }

        @lazy
        static get imageGetClassCount() {
            return this.r("il2cpp_image_get_class_count", "uint32", ["pointer"]);
        }

        @lazy
        static get imageGetName() {
            return this.r("il2cpp_image_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get init() {
            return this.r("il2cpp_init", "void", ["pointer"]);
        }

        @lazy
        static get livenessAllocateStruct() {
            return this.r("il2cpp_unity_liveness_allocate_struct", "pointer", ["pointer", "int", "pointer", "pointer", "pointer"]);
        }

        @lazy
        static get livenessCalculationBegin() {
            return this.r("il2cpp_unity_liveness_calculation_begin", "pointer", ["pointer", "int", "pointer", "pointer", "pointer", "pointer"]);
        }

        @lazy
        static get livenessCalculationEnd() {
            return this.r("il2cpp_unity_liveness_calculation_end", "void", ["pointer"]);
        }

        @lazy
        static get livenessCalculationFromStatics() {
            return this.r("il2cpp_unity_liveness_calculation_from_statics", "void", ["pointer"]);
        }

        @lazy
        static get livenessFinalize() {
            return this.r("il2cpp_unity_liveness_finalize", "void", ["pointer"]);
        }

        @lazy
        static get livenessFreeStruct() {
            return this.r("il2cpp_unity_liveness_free_struct", "void", ["pointer"]);
        }

        @lazy
        static get memorySnapshotCapture() {
            return this.r("il2cpp_capture_memory_snapshot", "pointer", []);
        }

        @lazy
        static get memorySnapshotFree() {
            return this.r("il2cpp_free_captured_memory_snapshot", "void", ["pointer"]);
        }

        @lazy
        static get memorySnapshotGetClasses() {
            return this.r("il2cpp_memory_snapshot_get_classes", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get memorySnapshotGetGCHandles() {
            return this.r("il2cpp_memory_snapshot_get_gc_handles", ["uint32", "pointer"], ["pointer"]);
        }

        @lazy
        static get memorySnapshotGetRuntimeInformation() {
            return this.r("il2cpp_memory_snapshot_get_information", ["uint32", "uint32", "uint32", "uint32", "uint32", "uint32"], ["pointer"]);
        }

        @lazy
        static get methodGetModifier() {
            return this.r("il2cpp_method_get_modifier", "pointer", ["pointer"]);
        }

        @lazy
        static get methodGetClass() {
            return this.r("il2cpp_method_get_class", "pointer", ["pointer"]);
        }

        @lazy
        static get methodGetFlags() {
            return this.r("il2cpp_method_get_flags", "uint32", ["pointer", "pointer"]);
        }

        @lazy
        static get methodGetFromReflection() {
            return this.r("il2cpp_method_get_from_reflection", "pointer", ["pointer"]);
        }

        @lazy
        static get methodGetName() {
            return this.r("il2cpp_method_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get methodGetObject() {
            return this.r("il2cpp_method_get_object", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get methodGetParameterCount() {
            return this.r("il2cpp_method_get_param_count", "uint8", ["pointer"]);
        }

        @lazy
        static get methodGetParameterName() {
            return this.r("il2cpp_method_get_param_name", "pointer", ["pointer", "uint32"]);
        }

        @lazy
        static get methodGetParameters() {
            return this.r("il2cpp_method_get_parameters", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get methodGetParameterType() {
            return this.r("il2cpp_method_get_param", "pointer", ["pointer", "uint32"]);
        }

        @lazy
        static get methodGetPointer() {
            return this.r("il2cpp_method_get_pointer", "pointer", ["pointer"]);
        }

        @lazy
        static get methodGetReturnType() {
            return this.r("il2cpp_method_get_return_type", "pointer", ["pointer"]);
        }

        @lazy
        static get methodIsExternal() {
            return this.r("il2cpp_method_is_external", "bool", ["pointer"]);
        }

        @lazy
        static get methodIsGeneric() {
            return this.r("il2cpp_method_is_generic", "bool", ["pointer"]);
        }

        @lazy
        static get methodIsInflated() {
            return this.r("il2cpp_method_is_inflated", "bool", ["pointer"]);
        }

        @lazy
        static get methodIsInstance() {
            return this.r("il2cpp_method_is_instance", "bool", ["pointer"]);
        }

        @lazy
        static get methodIsSynchronized() {
            return this.r("il2cpp_method_is_synchronized", "bool", ["pointer"]);
        }

        @lazy
        static get monitorEnter() {
            return this.r("il2cpp_monitor_enter", "void", ["pointer"]);
        }

        @lazy
        static get monitorExit() {
            return this.r("il2cpp_monitor_exit", "void", ["pointer"]);
        }

        @lazy
        static get monitorPulse() {
            return this.r("il2cpp_monitor_pulse", "void", ["pointer"]);
        }

        @lazy
        static get monitorPulseAll() {
            return this.r("il2cpp_monitor_pulse_all", "void", ["pointer"]);
        }

        @lazy
        static get monitorTryEnter() {
            return this.r("il2cpp_monitor_try_enter", "bool", ["pointer", "uint32"]);
        }

        @lazy
        static get monitorTryWait() {
            return this.r("il2cpp_monitor_try_wait", "bool", ["pointer", "uint32"]);
        }

        @lazy
        static get monitorWait() {
            return this.r("il2cpp_monitor_wait", "void", ["pointer"]);
        }

        @lazy
        static get objectGetClass() {
            return this.r("il2cpp_object_get_class", "pointer", ["pointer"]);
        }

        @lazy
        static get objectGetVirtualMethod() {
            return this.r("il2cpp_object_get_virtual_method", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get objectInit() {
            return this.r("il2cpp_runtime_object_init_exception", "void", ["pointer", "pointer"]);
        }

        @lazy
        static get objectNew() {
            return this.r("il2cpp_object_new", "pointer", ["pointer"]);
        }

        @lazy
        static get objectGetSize() {
            return this.r("il2cpp_object_get_size", "uint32", ["pointer"]);
        }

        @lazy
        static get objectUnbox() {
            return this.r("il2cpp_object_unbox", "pointer", ["pointer"]);
        }

        @lazy
        static get resolveInternalCall() {
            return this.r("il2cpp_resolve_icall", "pointer", ["pointer"]);
        }

        @lazy
        static get stringChars() {
            return this.r("il2cpp_string_chars", "pointer", ["pointer"]);
        }

        @lazy
        static get stringLength() {
            return this.r("il2cpp_string_length", "int32", ["pointer"]);
        }

        @lazy
        static get stringNew() {
            return this.r("il2cpp_string_new", "pointer", ["pointer"]);
        }

        @lazy
        static get stringSetLength() {
            return this.r("il2cpp_string_set_length", "void", ["pointer", "int32"]);
        }

        @lazy
        static get valueBox() {
            return this.r("il2cpp_value_box", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get threadAttach() {
            return this.r("il2cpp_thread_attach", "pointer", ["pointer"]);
        }

        @lazy
        static get threadCurrent() {
            return this.r("il2cpp_thread_current", "pointer", []);
        }

        @lazy
        static get threadGetAllAttachedThreads() {
            return this.r("il2cpp_thread_get_all_attached_threads", "pointer", ["pointer"]);
        }

        @lazy
        static get threadIsVm() {
            return this.r("il2cpp_is_vm_thread", "bool", ["pointer"]);
        }

        @lazy
        static get threadDetach() {
            return this.r("il2cpp_thread_detach", "void", ["pointer"]);
        }

        @lazy
        static get typeGetName() {
            return this.r("il2cpp_type_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get typeGetObject() {
            return this.r("il2cpp_type_get_object", "pointer", ["pointer"]);
        }

        @lazy
        static get typeGetTypeEnum() {
            return this.r("il2cpp_type_get_type", "int", ["pointer"]);
        }

        @lazy
        static get typeIsByReference() {
            return this.r("il2cpp_type_is_byref", "bool", ["pointer"]);
        }

        @lazy
        static get typeIsPrimitive() {
            return this.r("il2cpp_type_is_primitive", "bool", ["pointer"]);
        }

        /** @internal */
        @lazy
        private static get cModule(): Record<string, NativePointer | null> {
            const offsetsFinderCModule = new CModule($inline_file("cmodules/offset-of.c"));

            const offsetOfInt32 = new NativeFunction(offsetsFinderCModule.offset_of_int32, "int16", ["pointer", "int32"]);
            const offsetOfPointer = new NativeFunction(offsetsFinderCModule.offset_of_pointer, "int16", ["pointer", "pointer"]);

            const SystemString = Il2Cpp.corlib.class("System.String");
            const SystemDateTime = Il2Cpp.corlib.class("System.DateTime");
            const SystemReflectionModule = Il2Cpp.corlib.class("System.Reflection.Module");

            SystemDateTime.initialize();
            SystemReflectionModule.initialize();

            const DaysToMonth365 = (
                SystemDateTime.tryField<Il2Cpp.Array<number>>("daysmonth") ??
                SystemDateTime.tryField<Il2Cpp.Array<number>>("DaysToMonth365") ??
                SystemDateTime.field<Il2Cpp.Array<number>>("s_daysToMonth365")
            ).value;

            const FilterTypeName = SystemReflectionModule.field<Il2Cpp.Object>("FilterTypeName").value;
            const FilterTypeNameMethodPointer = FilterTypeName.field<NativePointer>("method_ptr").value;
            const FilterTypeNameMethod = FilterTypeName.field<NativePointer>("method").value;
            const FilterTypeNameInvoke = FilterTypeName.method("Invoke");

            const defines = `
                #define IL2CPP_STRING_SET_LENGTH_OFFSET ${offsetOfInt32(Il2Cpp.string("vfsfitvnm"), 9)}
                #define IL2CPP_ARRAY_GET_ELEMENTS_OFFSET ${offsetOfInt32(DaysToMonth365, 31) - 1}
                #define IL2CPP_CLASS_GET_ACTUAL_INSTANCE_SIZE_OFFSET ${offsetOfInt32(SystemString, SystemString.instanceSize - 2)}
                #define IL2CPP_METHOD_GET_POINTER_OFFSET ${offsetOfPointer(FilterTypeNameMethod, FilterTypeNameMethodPointer)}
                #define IL2CPP_METHOD_GET_FROM_REFLECTION_OFFSET ${offsetOfPointer(FilterTypeNameInvoke.object, FilterTypeNameInvoke)}
            `;

            offsetsFinderCModule.dispose();

            const cModule = new CModule(defines + $inline_file("cmodules/api.c") + $inline_file("cmodules/memory-snapshot.c"), {
                il2cpp_class_from_name: this.classFromName,
                il2cpp_class_get_method_from_name: this.classGetMethodFromName,
                il2cpp_class_get_name: this.classGetName,
                il2cpp_field_get_flags: this.fieldGetFlags,
                il2cpp_field_get_offset: this.fieldGetOffset,
                il2cpp_free: this.free,
                il2cpp_image_get_corlib: this.getCorlib,
                il2cpp_method_get_flags: this.methodGetFlags,
                il2cpp_type_get_name: this.typeGetName,
                il2cpp_type_get_type_enum: this.typeGetTypeEnum
            });

            return cModule;
        }

        /** @internal */
        private static r<R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(exportName: string, retType: R, argTypes: A) {
            const exportPointer = Il2Cpp.module.findExportByName(exportName) ?? this.cModule[exportName];

            if (exportPointer == null) {
                raise(`cannot resolve export ${exportName}`);
            }

            return new NativeFunction(exportPointer, retType, argTypes);
        }
    }
}

/** @internal */
declare const $inline_file: typeof import("ts-transformer-inline-file").$INLINE_FILE;
