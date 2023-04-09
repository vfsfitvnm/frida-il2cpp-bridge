namespace Il2Cpp {
    export class Api {
        protected constructor() {}

        @lazy
        static get _alloc() {
            return this.r("il2cpp_alloc", "pointer", ["size_t"]);
        }

        @lazy
        static get _arrayGetElements() {
            return this.r("il2cpp_array_get_elements", "pointer", ["pointer"]);
        }

        @lazy
        static get _arrayGetLength() {
            return this.r("il2cpp_array_length", "uint32", ["pointer"]);
        }

        @lazy
        static get _arrayNew() {
            return this.r("il2cpp_array_new", "pointer", ["pointer", "uint32"]);
        }

        @lazy
        static get _assemblyGetImage() {
            return this.r("il2cpp_assembly_get_image", "pointer", ["pointer"]);
        }

        @lazy
        static get _classForEach() {
            return this.r("il2cpp_class_for_each", "void", ["pointer", "pointer"]);
        }

        @lazy
        static get _classFromName() {
            return this.r("il2cpp_class_from_name", "pointer", ["pointer", "pointer", "pointer"]);
        }

        @lazy
        static get _classFromSystemType() {
            return this.r("il2cpp_class_from_system_type", "pointer", ["pointer"]);
        }

        @lazy
        static get _classFromType() {
            return this.r("il2cpp_class_from_type", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetActualInstanceSize() {
            return this.r("il2cpp_class_get_actual_instance_size", "int32", ["pointer"]);
        }

        @lazy
        static get _classGetArrayClass() {
            return this.r("il2cpp_array_class_get", "pointer", ["pointer", "uint32"]);
        }

        @lazy
        static get _classGetArrayElementSize() {
            return this.r("il2cpp_class_array_element_size", "int", ["pointer"]);
        }

        @lazy
        static get _classGetAssemblyName() {
            return this.r("il2cpp_class_get_assemblyname", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetBaseType() {
            return this.r("il2cpp_class_enum_basetype", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetDeclaringType() {
            return this.r("il2cpp_class_get_declaring_type", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetElementClass() {
            return this.r("il2cpp_class_get_element_class", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetFieldFromName() {
            return this.r("il2cpp_class_get_field_from_name", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _classGetFields() {
            return this.r("il2cpp_class_get_fields", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _classGetFlags() {
            return this.r("il2cpp_class_get_flags", "int", ["pointer"]);
        }

        @lazy
        static get _classGetImage() {
            return this.r("il2cpp_class_get_image", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetInstanceSize() {
            return this.r("il2cpp_class_instance_size", "int32", ["pointer"]);
        }

        @lazy
        static get _classGetInterfaces() {
            return this.r("il2cpp_class_get_interfaces", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _classGetMethodFromName() {
            return this.r("il2cpp_class_get_method_from_name", "pointer", ["pointer", "pointer", "int"]);
        }

        @lazy
        static get _classGetMethods() {
            return this.r("il2cpp_class_get_methods", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _classGetName() {
            return this.r("il2cpp_class_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetNamespace() {
            return this.r("il2cpp_class_get_namespace", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetNestedClasses() {
            return this.r("il2cpp_class_get_nested_types", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _classGetParent() {
            return this.r("il2cpp_class_get_parent", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetRank() {
            return this.r("il2cpp_class_get_rank", "int", ["pointer"]);
        }

        @lazy
        static get _classGetStaticFieldData() {
            return this.r("il2cpp_class_get_static_field_data", "pointer", ["pointer"]);
        }

        @lazy
        static get _classGetValueSize() {
            return this.r("il2cpp_class_value_size", "int32", ["pointer", "pointer"]);
        }

        @lazy
        static get _classGetType() {
            return this.r("il2cpp_class_get_type", "pointer", ["pointer"]);
        }

        @lazy
        static get _classHasReferences() {
            return this.r("il2cpp_class_has_references", "bool", ["pointer"]);
        }

        @lazy
        static get _classInit() {
            return this.r("il2cpp_runtime_class_init", "void", ["pointer"]);
        }

        @lazy
        static get _classIsAbstract() {
            return this.r("il2cpp_class_is_abstract", "bool", ["pointer"]);
        }

        @lazy
        static get _classIsAssignableFrom() {
            return this.r("il2cpp_class_is_assignable_from", "bool", ["pointer", "pointer"]);
        }

        @lazy
        static get _classIsBlittable() {
            return this.r("il2cpp_class_is_blittable", "bool", ["pointer"]);
        }

        @lazy
        static get _classIsEnum() {
            return this.r("il2cpp_class_is_enum", "bool", ["pointer"]);
        }

        @lazy
        static get _classIsGeneric() {
            return this.r("il2cpp_class_is_generic", "bool", ["pointer"]);
        }

        @lazy
        static get _classIsInflated() {
            return this.r("il2cpp_class_is_inflated", "bool", ["pointer"]);
        }

        @lazy
        static get _classIsInterface() {
            return this.r("il2cpp_class_is_interface", "bool", ["pointer"]);
        }

        @lazy
        static get _classIsSubclassOf() {
            return this.r("il2cpp_class_is_subclass_of", "bool", ["pointer", "pointer", "bool"]);
        }

        @lazy
        static get _classIsValueType() {
            return this.r("il2cpp_class_is_valuetype", "bool", ["pointer"]);
        }

        @lazy
        static get _domainAssemblyOpen() {
            return this.r("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _domainGet() {
            return this.r("il2cpp_domain_get", "pointer", []);
        }

        @lazy
        static get _domainGetAssemblies() {
            return this.r("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _domainGetObject() {
            return this.r("il2cpp_domain_get_object", "pointer", []);
        }

        @lazy
        static get _fieldGetModifier() {
            return this.r("il2cpp_field_get_modifier", "pointer", ["pointer"]);
        }

        @lazy
        static get _fieldGetClass() {
            return this.r("il2cpp_field_get_parent", "pointer", ["pointer"]);
        }

        @lazy
        static get _fieldGetFlags() {
            return this.r("il2cpp_field_get_flags", "int", ["pointer"]);
        }

        @lazy
        static get _fieldGetName() {
            return this.r("il2cpp_field_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get _fieldGetOffset() {
            return this.r("il2cpp_field_get_offset", "int32", ["pointer"]);
        }

        @lazy
        static get _fieldGetStaticValue() {
            return this.r("il2cpp_field_static_get_value", "void", ["pointer", "pointer"]);
        }

        @lazy
        static get _fieldGetType() {
            return this.r("il2cpp_field_get_type", "pointer", ["pointer"]);
        }

        @lazy
        static get _fieldIsLiteral() {
            return this.r("il2cpp_field_is_literal", "bool", ["pointer"]);
        }

        @lazy
        static get _fieldIsStatic() {
            return this.r("il2cpp_field_is_static", "bool", ["pointer"]);
        }

        @lazy
        static get _fieldIsThreadStatic() {
            return this.r("il2cpp_field_is_thread_static", "bool", ["pointer"]);
        }

        @lazy
        static get _fieldSetStaticValue() {
            return this.r("il2cpp_field_static_set_value", "void", ["pointer", "pointer"]);
        }

        @lazy
        static get _free() {
            return this.r("il2cpp_free", "void", ["pointer"]);
        }

        @lazy
        static get _gcCollect() {
            return this.r("il2cpp_gc_collect", "void", ["int"]);
        }

        @lazy
        static get _gcCollectALittle() {
            return this.r("il2cpp_gc_collect_a_little", "void", []);
        }

        @lazy
        static get _gcDisable() {
            return this.r("il2cpp_gc_disable", "void", []);
        }

        @lazy
        static get _gcEnable() {
            return this.r("il2cpp_gc_enable", "void", []);
        }

        @lazy
        static get _gcGetHeapSize() {
            return this.r("il2cpp_gc_get_heap_size", "int64", []);
        }

        @lazy
        static get _gcGetMaxTimeSlice() {
            return this.r("il2cpp_gc_get_max_time_slice_ns", "int64", []);
        }

        @lazy
        static get _gcGetUsedSize() {
            return this.r("il2cpp_gc_get_used_size", "int64", []);
        }

        @lazy
        static get _gcHandleGetTarget() {
            return this.r("il2cpp_gchandle_get_target", "pointer", ["uint32"]);
        }

        @lazy
        static get _gcHandleFree() {
            return this.r("il2cpp_gchandle_free", "void", ["uint32"]);
        }

        @lazy
        static get _gcHandleNew() {
            return this.r("il2cpp_gchandle_new", "uint32", ["pointer", "bool"]);
        }

        @lazy
        static get _gcHandleNewWeakRef() {
            return this.r("il2cpp_gchandle_new_weakref", "uint32", ["pointer", "bool"]);
        }

        @lazy
        static get _gcIsDisabled() {
            return this.r("il2cpp_gc_is_disabled", "bool", []);
        }

        @lazy
        static get _gcIsIncremental() {
            return this.r("il2cpp_gc_is_incremental", "bool", []);
        }

        @lazy
        static get _gcSetMaxTimeSlice() {
            return this.r("il2cpp_gc_set_max_time_slice_ns", "void", ["int64"]);
        }

        @lazy
        static get _gcStartIncrementalCollection() {
            return this.r("il2cpp_gc_start_incremental_collection", "void", []);
        }

        @lazy
        static get _gcStartWorld() {
            return this.r("il2cpp_start_gc_world", "void", []);
        }

        @lazy
        static get _gcStopWorld() {
            return this.r("il2cpp_stop_gc_world", "void", []);
        }

        @lazy
        static get _getCorlib() {
            return this.r("il2cpp_get_corlib", "pointer", []);
        }

        @lazy
        static get _imageGetAssembly() {
            return this.r("il2cpp_image_get_assembly", "pointer", ["pointer"]);
        }

        @lazy
        static get _imageGetClass() {
            return this.r("il2cpp_image_get_class", "pointer", ["pointer", "uint"]);
        }

        @lazy
        static get _imageGetClassCount() {
            return this.r("il2cpp_image_get_class_count", "uint32", ["pointer"]);
        }

        @lazy
        static get _imageGetName() {
            return this.r("il2cpp_image_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get _init() {
            return this.r("il2cpp_init", "void", []);
        }

        @lazy
        static get _livenessAllocateStruct() {
            return this.r("il2cpp_unity_liveness_allocate_struct", "pointer", ["pointer", "int", "pointer", "pointer", "pointer"]);
        }

        @lazy
        static get _livenessCalculationBegin() {
            return this.r("il2cpp_unity_liveness_calculation_begin", "pointer", ["pointer", "int", "pointer", "pointer", "pointer", "pointer"]);
        }

        @lazy
        static get _livenessCalculationEnd() {
            return this.r("il2cpp_unity_liveness_calculation_end", "void", ["pointer"]);
        }

        @lazy
        static get _livenessCalculationFromStatics() {
            return this.r("il2cpp_unity_liveness_calculation_from_statics", "void", ["pointer"]);
        }

        @lazy
        static get _livenessFinalize() {
            return this.r("il2cpp_unity_liveness_finalize", "void", ["pointer"]);
        }

        @lazy
        static get _livenessFreeStruct() {
            return this.r("il2cpp_unity_liveness_free_struct", "void", ["pointer"]);
        }

        @lazy
        static get _memorySnapshotCapture() {
            return this.r("il2cpp_capture_memory_snapshot", "pointer", []);
        }

        @lazy
        static get _memorySnapshotFree() {
            return this.r("il2cpp_free_captured_memory_snapshot", "void", ["pointer"]);
        }

        @lazy
        static get _memorySnapshotGetClasses() {
            return this.r("il2cpp_memory_snapshot_get_classes", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _memorySnapshotGetGCHandles() {
            return this.r("il2cpp_memory_snapshot_get_gc_handles", ["uint32", "pointer"], ["pointer"]);
        }

        @lazy
        static get _memorySnapshotGetRuntimeInformation() {
            return this.r("il2cpp_memory_snapshot_get_information", ["uint32", "uint32", "uint32", "uint32", "uint32", "uint32"], ["pointer"]);
        }

        @lazy
        static get _methodGetModifier() {
            return this.r("il2cpp_method_get_modifier", "pointer", ["pointer"]);
        }

        @lazy
        static get _methodGetClass() {
            return this.r("il2cpp_method_get_class", "pointer", ["pointer"]);
        }

        @lazy
        static get _methodGetFlags() {
            return this.r("il2cpp_method_get_flags", "uint32", ["pointer", "pointer"]);
        }

        @lazy
        static get _methodGetFromReflection() {
            return this.r("il2cpp_method_get_from_reflection", "pointer", ["pointer"]);
        }

        @lazy
        static get _methodGetName() {
            return this.r("il2cpp_method_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get _methodGetObject() {
            return this.r("il2cpp_method_get_object", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _methodGetParameterCount() {
            return this.r("il2cpp_method_get_param_count", "uint8", ["pointer"]);
        }

        @lazy
        static get _methodGetParameterName() {
            return this.r("il2cpp_method_get_param_name", "pointer", ["pointer", "uint32"]);
        }

        @lazy
        static get _methodGetParameters() {
            return this.r("il2cpp_method_get_parameters", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _methodGetParameterType() {
            return this.r("il2cpp_method_get_param", "pointer", ["pointer", "uint32"]);
        }

        @lazy
        static get _methodGetPointer() {
            return this.r("il2cpp_method_get_pointer", "pointer", ["pointer"]);
        }

        @lazy
        static get _methodGetReturnType() {
            return this.r("il2cpp_method_get_return_type", "pointer", ["pointer"]);
        }

        @lazy
        static get _methodIsExternal() {
            return this.r("il2cpp_method_is_external", "bool", ["pointer"]);
        }

        @lazy
        static get _methodIsGeneric() {
            return this.r("il2cpp_method_is_generic", "bool", ["pointer"]);
        }

        @lazy
        static get _methodIsInflated() {
            return this.r("il2cpp_method_is_inflated", "bool", ["pointer"]);
        }

        @lazy
        static get _methodIsInstance() {
            return this.r("il2cpp_method_is_instance", "bool", ["pointer"]);
        }

        @lazy
        static get _methodIsSynchronized() {
            return this.r("il2cpp_method_is_synchronized", "bool", ["pointer"]);
        }

        @lazy
        static get _monitorEnter() {
            return this.r("il2cpp_monitor_enter", "void", ["pointer"]);
        }

        @lazy
        static get _monitorExit() {
            return this.r("il2cpp_monitor_exit", "void", ["pointer"]);
        }

        @lazy
        static get _monitorPulse() {
            return this.r("il2cpp_monitor_pulse", "void", ["pointer"]);
        }

        @lazy
        static get _monitorPulseAll() {
            return this.r("il2cpp_monitor_pulse_all", "void", ["pointer"]);
        }

        @lazy
        static get _monitorTryEnter() {
            return this.r("il2cpp_monitor_try_enter", "bool", ["pointer", "uint32"]);
        }

        @lazy
        static get _monitorTryWait() {
            return this.r("il2cpp_monitor_try_wait", "bool", ["pointer", "uint32"]);
        }

        @lazy
        static get _monitorWait() {
            return this.r("il2cpp_monitor_wait", "void", ["pointer"]);
        }

        @lazy
        static get _objectGetClass() {
            return this.r("il2cpp_object_get_class", "pointer", ["pointer"]);
        }

        @lazy
        static get _objectGetVirtualMethod() {
            return this.r("il2cpp_object_get_virtual_method", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _objectInit() {
            return this.r("il2cpp_runtime_object_init_exception", "void", ["pointer", "pointer"]);
        }

        @lazy
        static get _objectNew() {
            return this.r("il2cpp_object_new", "pointer", ["pointer"]);
        }

        @lazy
        static get _objectGetSize() {
            return this.r("il2cpp_object_get_size", "uint32", ["pointer"]);
        }

        @lazy
        static get _objectUnbox() {
            return this.r("il2cpp_object_unbox", "pointer", ["pointer"]);
        }

        @lazy
        static get _resolveInternalCall() {
            return this.r("il2cpp_resolve_icall", "pointer", ["pointer"]);
        }

        @lazy
        static get _stringChars() {
            return this.r("il2cpp_string_chars", "pointer", ["pointer"]);
        }

        @lazy
        static get _stringLength() {
            return this.r("il2cpp_string_length", "int32", ["pointer"]);
        }

        @lazy
        static get _stringNew() {
            return this.r("il2cpp_string_new", "pointer", ["pointer"]);
        }

        @lazy
        static get _stringSetLength() {
            return this.r("il2cpp_string_set_length", "void", ["pointer", "int32"]);
        }

        @lazy
        static get _valueBox() {
            return this.r("il2cpp_value_box", "pointer", ["pointer", "pointer"]);
        }

        @lazy
        static get _threadAttach() {
            return this.r("il2cpp_thread_attach", "pointer", ["pointer"]);
        }

        @lazy
        static get _threadCurrent() {
            return this.r("il2cpp_thread_current", "pointer", []);
        }

        @lazy
        static get _threadGetAllAttachedThreads() {
            return this.r("il2cpp_thread_get_all_attached_threads", "pointer", ["pointer"]);
        }

        @lazy
        static get _threadIsVm() {
            return this.r("il2cpp_is_vm_thread", "bool", ["pointer"]);
        }

        @lazy
        static get _threadDetach() {
            return this.r("il2cpp_thread_detach", "void", ["pointer"]);
        }

        @lazy
        static get _typeGetName() {
            return this.r("il2cpp_type_get_name", "pointer", ["pointer"]);
        }

        @lazy
        static get _typeGetObject() {
            return this.r("il2cpp_type_get_object", "pointer", ["pointer"]);
        }

        @lazy
        static get _typeGetTypeEnum() {
            return this.r("il2cpp_type_get_type", "int", ["pointer"]);
        }

        @lazy
        static get _typeIsByReference() {
            return this.r("il2cpp_type_is_byref", "bool", ["pointer"]);
        }

        @lazy
        static get _typeIsPrimitive() {
            return this.r("il2cpp_type_is_primitive", "bool", ["pointer"]);
        }

        /** @internal */
        @lazy
        private static get cModule(): Record<string, NativePointer | null> {
            const offsetsFinderCModule = new CModule($INLINE_FILE("cmodules/offset-of.c"));

            const offsetOfInt32 = new NativeFunction(offsetsFinderCModule.offset_of_int32, "int16", ["pointer", "int32"]);
            const offsetOfPointer = new NativeFunction(offsetsFinderCModule.offset_of_pointer, "int16", ["pointer", "pointer"]);

            const SystemString = Il2Cpp.Image.corlib.class("System.String");
            const SystemDateTime = Il2Cpp.Image.corlib.class("System.DateTime");
            const SystemReflectionModule = Il2Cpp.Image.corlib.class("System.Reflection.Module");

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
            #define IL2CPP_STRING_SET_LENGTH_OFFSET ${offsetOfInt32(Il2Cpp.String.from("vfsfitvnm"), 9)}
            #define IL2CPP_ARRAY_GET_ELEMENTS_OFFSET ${offsetOfInt32(DaysToMonth365, 31) - 1}
            #define IL2CPP_CLASS_GET_ACTUAL_INSTANCE_SIZE_OFFSET ${offsetOfInt32(SystemString, SystemString.instanceSize - 2)}
            #define IL2CPP_METHOD_GET_POINTER_OFFSET ${offsetOfPointer(FilterTypeNameMethod, FilterTypeNameMethodPointer)}
            #define IL2CPP_METHOD_GET_FROM_REFLECTION_OFFSET ${offsetOfPointer(FilterTypeNameInvoke.object, FilterTypeNameInvoke)}
            `;

            offsetsFinderCModule.dispose();

            const cModule = new CModule(defines + $INLINE_FILE("cmodules/api.c") + $INLINE_FILE("cmodules/memory-snapshot.c"), {
                il2cpp_class_from_name: this._classFromName,
                il2cpp_class_get_method_from_name: this._classGetMethodFromName,
                il2cpp_class_get_name: this._classGetName,
                il2cpp_field_get_flags: this._fieldGetFlags,
                il2cpp_field_get_offset: this._fieldGetOffset,
                il2cpp_free: this._free,
                il2cpp_image_get_corlib: this._getCorlib,
                il2cpp_method_get_flags: this._methodGetFlags,
                il2cpp_type_get_name: this._typeGetName,
                il2cpp_type_get_type_enum: this._typeGetTypeEnum
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
