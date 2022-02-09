import { cache } from "decorator-cache-getter";
import { read } from "./utils";
import { raise, warn } from "../utils/console";

class Il2CppApi {
    protected constructor() {}

    @cache
    static get _alloc() {
        return this.r("il2cpp_alloc", "pointer", ["size_t"]);
    }

    @cache
    static get _arrayGetElements() {
        return this.r("il2cpp_array_get_elements", "pointer", ["pointer"]);
    }

    @cache
    static get _arrayGetLength() {
        return this.r("il2cpp_array_length", "uint32", ["pointer"]);
    }

    @cache
    static get _arrayNew() {
        return this.r("il2cpp_array_new", "pointer", ["pointer", "uint32"]);
    }

    @cache
    static get _assemblyGetImage() {
        return this.r("il2cpp_assembly_get_image", "pointer", ["pointer"]);
    }

    @cache
    static get _classForEach() {
        return this.r("il2cpp_class_for_each", "void", ["pointer", "pointer"], "2019.3.0");
    }

    @cache
    static get _classFromName() {
        return this.r("il2cpp_class_from_name", "pointer", ["pointer", "pointer", "pointer"]);
    }

    @cache
    static get _classFromSystemType() {
        return this.r("il2cpp_class_from_system_type", "pointer", ["pointer"]);
    }

    @cache
    static get _classFromType() {
        return this.r("il2cpp_class_from_type", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetActualInstanceSize() {
        return this.r("il2cpp_class_get_actual_instance_size", "int32", ["pointer"]);
    }

    @cache
    static get _classGetArrayClass() {
        return this.r("il2cpp_array_class_get", "pointer", ["pointer", "uint32"]);
    }

    @cache
    static get _classGetArrayElementSize() {
        return this.r("il2cpp_class_array_element_size", "int", ["pointer"]);
    }

    @cache
    static get _classGetAssemblyName() {
        return this.r("il2cpp_class_get_assemblyname", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetBaseType() {
        return this.r("il2cpp_class_enum_basetype", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetDeclaringType() {
        return this.r("il2cpp_class_get_declaring_type", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetElementClass() {
        return this.r("il2cpp_class_get_element_class", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetFieldCount() {
        return this.r("il2cpp_class_num_fields", "size_t", ["pointer"]);
    }

    @cache
    static get _classGetFieldFromName() {
        return this.r("il2cpp_class_get_field_from_name", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _classGetFields() {
        return this.r("il2cpp_class_get_fields", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _classGetFlags() {
        return this.r("il2cpp_class_get_flags", "int", ["pointer"]);
    }

    @cache
    static get _classGetImage() {
        return this.r("il2cpp_class_get_image", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetInstanceSize() {
        return this.r("il2cpp_class_instance_size", "int32", ["pointer"]);
    }

    @cache
    static get _classGetInterfaceCount() {
        return this.r("il2cpp_class_get_interface_count", "uint16", ["pointer"]);
    }

    @cache
    static get _classGetInterfaces() {
        return this.r("il2cpp_class_get_interfaces", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _classGetMethodCount() {
        return this.r("il2cpp_class_get_method_count", "uint16", ["pointer"]);
    }

    @cache
    static get _classGetMethodFromName() {
        return this.r("il2cpp_class_get_method_from_name", "pointer", ["pointer", "pointer", "int"]);
    }

    @cache
    static get _classGetMethods() {
        return this.r("il2cpp_class_get_methods", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _classGetName() {
        return this.r("il2cpp_class_get_name", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetNamespace() {
        return this.r("il2cpp_class_get_namespace", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetNestedClasses() {
        return this.r("il2cpp_class_get_nested_types", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _classGetParent() {
        return this.r("il2cpp_class_get_parent", "pointer", ["pointer"]);
    }

    @cache
    static get _classGetRank() {
        return this.r("il2cpp_class_get_rank", "int", ["pointer"]);
    }

    @cache
    static get _classGetStaticFieldData() {
        return this.r("il2cpp_class_get_static_field_data", "pointer", ["pointer"], "2019.3.0");
    }

    @cache
    static get _classGetValueSize() {
        return this.r("il2cpp_class_value_size", "int32", ["pointer", "pointer"]);
    }

    @cache
    static get _classGetType() {
        return this.r("il2cpp_class_get_type", "pointer", ["pointer"]);
    }

    @cache
    static get _classHasReferences() {
        return this.r("il2cpp_class_has_references", "bool", ["pointer"]);
    }

    @cache
    static get _classInit() {
        return this.r("il2cpp_runtime_class_init", "void", ["pointer"]);
    }

    @cache
    static get _classIsAbstract() {
        return this.r("il2cpp_class_is_abstract", "bool", ["pointer"]);
    }

    @cache
    static get _classIsAssignableFrom() {
        return this.r("il2cpp_class_is_assignable_from", "bool", ["pointer", "pointer"]);
    }

    @cache
    static get _classIsBlittable() {
        return this.r("il2cpp_class_is_blittable", "bool", ["pointer"], "2017.1.0");
    }

    @cache
    static get _classIsEnum() {
        return this.r("il2cpp_class_is_enum", "bool", ["pointer"]);
    }

    @cache
    static get _classIsGeneric() {
        return this.r("il2cpp_class_is_generic", "bool", ["pointer"]);
    }

    @cache
    static get _classIsInflated() {
        return this.r("il2cpp_class_is_inflated", "bool", ["pointer"]);
    }

    @cache
    static get _classIsInterface() {
        return this.r("il2cpp_class_is_interface", "bool", ["pointer"]);
    }

    @cache
    static get _classIsSubclassOf() {
        return this.r("il2cpp_class_is_subclass_of", "bool", ["pointer", "pointer", "bool"]);
    }

    @cache
    static get _classToString() {
        return this.r("il2cpp_class_to_string", "void", ["pointer", "pointer"]);
    }

    @cache
    static get _classIsValueType() {
        return this.r("il2cpp_class_is_valuetype", "bool", ["pointer"]);
    }

    @cache
    static get _domainAssemblyOpen() {
        return this.r("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _domainGet() {
        return this.r("il2cpp_domain_get", "pointer", []);
    }

    @cache
    static get _domainGetAssemblies() {
        return this.r("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _fieldGetModifier() {
        return this.r("il2cpp_field_get_modifier", "pointer", ["pointer"]);
    }

    @cache
    static get _fieldGetClass() {
        return this.r("il2cpp_field_get_parent", "pointer", ["pointer"]);
    }

    @cache
    static get _fieldGetFlags() {
        return this.r("il2cpp_field_get_flags", "int", ["pointer"]);
    }

    @cache
    static get _fieldGetName() {
        return this.r("il2cpp_field_get_name", "pointer", ["pointer"]);
    }

    @cache
    static get _fieldGetOffset() {
        return this.r("il2cpp_field_get_offset", "int32", ["pointer"]);
    }

    @cache
    static get _fieldGetStaticValue() {
        return this.r("il2cpp_field_static_get_value", "void", ["pointer", "pointer"]);
    }

    @cache
    static get _fieldGetType() {
        return this.r("il2cpp_field_get_type", "pointer", ["pointer"]);
    }

    @cache
    static get _fieldIsLiteral() {
        return this.r("il2cpp_field_is_literal", "bool", ["pointer"]);
    }

    @cache
    static get _fieldIsStatic() {
        return this.r("il2cpp_field_is_static", "bool", ["pointer"]);
    }

    @cache
    static get _fieldIsThreadStatic() {
        return this.r("il2cpp_field_is_thread_static", "bool", ["pointer"]);
    }

    @cache
    static get _fieldSetStaticValue() {
        return this.r("il2cpp_field_static_set_value", "void", ["pointer", "pointer"]);
    }

    @cache
    static get _fieldToString() {
        return this.r("il2cpp_field_to_string", "void", ["pointer", "pointer"]);
    }

    @cache
    static get _free() {
        return this.r("il2cpp_free", "void", ["pointer"]);
    }

    @cache
    static get _gcCollect() {
        return this.r("il2cpp_gc_collect", "void", ["int"]);
    }

    @cache
    static get _gcCollectALittle() {
        return this.r("il2cpp_gc_collect_a_little", "void", [], "5.3.5");
    }

    @cache
    static get _gcDisable() {
        return this.r("il2cpp_gc_disable", "void", [], "5.3.5");
    }

    @cache
    static get _gcEnable() {
        return this.r("il2cpp_gc_enable", "void", [], "5.3.5");
    }

    @cache
    static get _gcGetHeapSize() {
        return this.r("il2cpp_gc_get_heap_size", "int64", []);
    }

    @cache
    static get _gcGetMaxTimeSlice() {
        return this.r("il2cpp_gc_get_max_time_slice_ns", "int64", [], "2019.1.0");
    }

    @cache
    static get _gcGetUsedSize() {
        return this.r("il2cpp_gc_get_used_size", "int64", []);
    }

    @cache
    static get _gcHandleGetTarget() {
        return this.r("il2cpp_gchandle_get_target", "pointer", ["uint32"]);
    }

    @cache
    static get _gcHandleFree() {
        return this.r("il2cpp_gchandle_free", "void", ["uint32"]);
    }

    @cache
    static get _gcHandleNew() {
        return this.r("il2cpp_gchandle_new", "uint32", ["pointer", "bool"]);
    }

    @cache
    static get _gcHandleNewWeakRef() {
        return this.r("il2cpp_gchandle_new_weakref", "uint32", ["pointer", "bool"]);
    }

    @cache
    static get _gcIsDisabled() {
        return this.r("il2cpp_gc_is_disabled", "bool", [], "2018.3.0");
    }

    @cache
    static get _gcIsIncremental() {
        return this.r("il2cpp_gc_is_incremental", "bool", [], "2019.1.0");
    }

    @cache
    static get _gcSetMaxTimeSlice() {
        return this.r("il2cpp_gc_set_max_time_slice_ns", "void", ["int64"], "2019.1.0");
    }

    @cache
    static get _gcStartIncrementalCollection() {
        return this.r("il2cpp_gc_start_incremental_collection", "void", [], "2020.2.0");
    }

    @cache
    static get _gcStartWorld() {
        return this.r("il2cpp_start_gc_world", "void", [], "2019.3.0");
    }

    @cache
    static get _gcStopWorld() {
        return this.r("il2cpp_stop_gc_world", "void", [], "2019.3.0");
    }

    @cache
    static get _getCorlib() {
        return this.r("il2cpp_get_corlib", "pointer", []);
    }

    @cache
    static get _imageGetAssembly() {
        return this.r("il2cpp_image_get_assembly", "pointer", ["pointer"]);
    }

    @cache
    static get _imageGetClass() {
        return this.r("il2cpp_image_get_class", "pointer", ["pointer", "uint"]);
    }

    @cache
    static get _imageGetClassCount() {
        return this.r("il2cpp_image_get_class_count", "uint32", ["pointer"], "2018.3.0");
    }

    @cache
    static get _imageGetName() {
        return this.r("il2cpp_image_get_name", "pointer", ["pointer"]);
    }

    @cache
    static get _init() {
        return this.r("il2cpp_init", "void", []);
    }

    @cache
    static get _livenessCalculationBegin() {
        return this.r("il2cpp_unity_liveness_calculation_begin", "pointer", ["pointer", "int", "pointer", "pointer", "pointer", "pointer"]);
    }

    @cache
    static get _livenessCalculationEnd() {
        return this.r("il2cpp_unity_liveness_calculation_end", "void", ["pointer"]);
    }

    @cache
    static get _livenessCalculationFromStatics() {
        return this.r("il2cpp_unity_liveness_calculation_from_statics", "void", ["pointer"]);
    }

    @cache
    static get _memorySnapshotCapture() {
        return this.r("il2cpp_capture_memory_snapshot", "pointer", []);
    }

    @cache
    static get _memorySnapshotFree() {
        return this.r("il2cpp_free_captured_memory_snapshot", "void", ["pointer"]);
    }

    @cache
    static get _memorySnapshotGetClasses() {
        return this.r("il2cpp_memory_snapshot_get_classes", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _memorySnapshotGetGCHandles() {
        return this.r("il2cpp_memory_snapshot_get_gc_handles", ["uint32", "pointer"], ["pointer"]);
    }

    @cache
    static get _memorySnapshotGetRuntimeInformation() {
        return this.r("il2cpp_memory_snapshot_get_information", ["uint32", "uint32", "uint32", "uint32", "uint32", "uint32"], ["pointer"]);
    }

    @cache
    static get _methodGetModifier() {
        return this.r("il2cpp_method_get_modifier", "pointer", ["pointer"]);
    }

    @cache
    static get _methodGetClass() {
        return this.r("il2cpp_method_get_class", "pointer", ["pointer"]);
    }

    @cache
    static get _methodGetFlags() {
        return this.r("il2cpp_method_get_flags", "uint32", ["pointer", "pointer"]);
    }

    @cache
    static get _methodGetFromReflection() {
        return this.r("il2cpp_method_get_from_reflection", "pointer", ["pointer"]);
    }

    @cache
    static get _methodGetName() {
        return this.r("il2cpp_method_get_name", "pointer", ["pointer"]);
    }

    @cache
    static get _methodGetObject() {
        return this.r("il2cpp_method_get_object", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _methodGetParameterCount() {
        return this.r("il2cpp_method_get_param_count", "uint8", ["pointer"]);
    }

    @cache
    static get _methodGetParameterName() {
        return this.r("il2cpp_method_get_param_name", "pointer", ["pointer", "uint32"]);
    }

    @cache
    static get _methodGetParameters() {
        return this.r("il2cpp_method_get_parameters", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _methodGetParameterType() {
        return this.r("il2cpp_method_get_param", "pointer", ["pointer", "uint32"]);
    }

    @cache
    static get _methodGetPointer() {
        return this.r("il2cpp_method_get_pointer", "pointer", ["pointer"]);
    }

    @cache
    static get _methodGetReturnType() {
        return this.r("il2cpp_method_get_return_type", "pointer", ["pointer"]);
    }

    @cache
    static get _methodIsExternal() {
        return this.r("il2cpp_method_is_external", "bool", ["pointer"]);
    }

    @cache
    static get _methodIsGeneric() {
        return this.r("il2cpp_method_is_generic", "bool", ["pointer"]);
    }

    @cache
    static get _methodIsInflated() {
        return this.r("il2cpp_method_is_inflated", "bool", ["pointer"]);
    }

    @cache
    static get _methodIsInstance() {
        return this.r("il2cpp_method_is_instance", "bool", ["pointer"]);
    }

    @cache
    static get _methodIsSynchronized() {
        return this.r("il2cpp_method_is_synchronized", "bool", ["pointer"]);
    }

    @cache
    static get _methodToString() {
        return this.r("il2cpp_method_to_string", "void", ["pointer", "pointer"]);
    }

    @cache
    static get _monitorEnter() {
        return this.r("il2cpp_monitor_enter", "void", ["pointer"]);
    }

    @cache
    static get _monitorExit() {
        return this.r("il2cpp_monitor_exit", "void", ["pointer"]);
    }

    @cache
    static get _monitorPulse() {
        return this.r("il2cpp_monitor_pulse", "void", ["pointer"]);
    }

    @cache
    static get _monitorPulseAll() {
        return this.r("il2cpp_monitor_pulse_all", "void", ["pointer"]);
    }

    @cache
    static get _monitorTryEnter() {
        return this.r("il2cpp_monitor_try_enter", "bool", ["pointer", "uint32"]);
    }

    @cache
    static get _monitorTryWait() {
        return this.r("il2cpp_monitor_try_wait", "bool", ["pointer", "uint32"]);
    }

    @cache
    static get _monitorWait() {
        return this.r("il2cpp_monitor_wait", "void", ["pointer"]);
    }

    @cache
    static get _objectGetClass() {
        return this.r("il2cpp_object_get_class", "pointer", ["pointer"]);
    }

    @cache
    static get _objectGetVirtualMethod() {
        return this.r("il2cpp_object_get_virtual_method", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _objectInit() {
        return this.r("il2cpp_runtime_object_init_exception", "void", ["pointer", "pointer"]);
    }

    @cache
    static get _objectNew() {
        return this.r("il2cpp_object_new", "pointer", ["pointer"]);
    }

    @cache
    static get _objectGetSize() {
        return this.r("il2cpp_object_get_size", "uint32", ["pointer"]);
    }

    @cache
    static get _objectUnbox() {
        return this.r("il2cpp_object_unbox", "pointer", ["pointer"]);
    }

    @cache
    static get _stringChars() {
        return this.r("il2cpp_string_chars", "pointer", ["pointer"]);
    }

    @cache
    static get _stringLength() {
        return this.r("il2cpp_string_length", "int32", ["pointer"]);
    }

    @cache
    static get _stringNew() {
        return this.r("il2cpp_string_new", "pointer", ["pointer"]);
    }

    @cache
    static get _stringSetLength() {
        return this.r("il2cpp_string_set_length", "void", ["pointer", "int32"]);
    }

    @cache
    static get _valueBox() {
        return this.r("il2cpp_value_box", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _threadAttach() {
        return this.r("il2cpp_thread_attach", "pointer", ["pointer"]);
    }

    @cache
    static get _threadCurrent() {
        return this.r("il2cpp_thread_current", "pointer", []);
    }

    @cache
    static get _threadGetAllAttachedThreads() {
        return this.r("il2cpp_thread_get_all_attached_threads", "pointer", ["pointer"]);
    }

    @cache
    static get _threadIsVm() {
        return this.r("il2cpp_is_vm_thread", "bool", ["pointer"]);
    }

    @cache
    static get _threadDetach() {
        return this.r("il2cpp_thread_detach", "void", ["pointer"]);
    }

    @cache
    static get _toString() {
        return this.r("il2cpp_struct_to_string", "pointer", ["pointer", "pointer"]);
    }

    @cache
    static get _typeGetName() {
        return this.r("il2cpp_type_get_name", "pointer", ["pointer"]);
    }

    @cache
    static get _typeGetObject() {
        return this.r("il2cpp_type_get_object", "pointer", ["pointer"]);
    }

    @cache
    static get _typeGetTypeEnum() {
        return this.r("il2cpp_type_get_type", "int", ["pointer"]);
    }

    @cache
    static get _typeIsByReference() {
        return this.r("il2cpp_type_is_byref", "bool", ["pointer"]);
    }

    @cache
    static get _typeIsPrimitive() {
        return this.r("il2cpp_type_is_primitive", "bool", ["pointer"]);
    }

    /** @internal */
    @cache
    private static get cModule(): Record<string, NativePointer | null> {
        if (Unity.mayBeUnsupported) {
            warn(`current Unity version ${Unity.version} is not supported, expect breakage`);
        }

        const offsetsFinderCModule = new CModule(`\
#include <stdint.h>

#define OFFSET_OF(name, type) \
    int16_t name (char * p,\
                  type e)\
    {\
        for (int16_t i = 0; i < 512; i++) if (* ((type *) p + i) == e) return i;\
        return -1;\
    }

OFFSET_OF (offset_of_uint16, uint16_t)
OFFSET_OF (offset_of_int32, int32_t)
OFFSET_OF (offset_of_pointer, void *)
            `);

        const offsetOfUInt16 = new NativeFunction(offsetsFinderCModule.offset_of_uint16, "int16", ["pointer", "uint16"]);
        const offsetOfInt32 = new NativeFunction(offsetsFinderCModule.offset_of_int32, "int16", ["pointer", "int32"]);
        const offsetOfPointer = new NativeFunction(offsetsFinderCModule.offset_of_pointer, "int16", ["pointer", "pointer"]);

        const SystemString = Il2Cpp.Image.corlib.class("System.String");
        const SystemValueType = Il2Cpp.Image.corlib.class("System.ValueType");
        const SystemDateTime = Il2Cpp.Image.corlib.class("System.DateTime");
        const SystemReflectionModule = Il2Cpp.Image.corlib.class("System.Reflection.Module");

        SystemDateTime.initialize();
        SystemReflectionModule.initialize();

        const DaysToMonth365 = (
            SystemDateTime.tryField<Il2Cpp.Array<number>>("daysmonth") || SystemDateTime.field<Il2Cpp.Array<number>>("DaysToMonth365")
        ).value;

        const filter_by_type_name = SystemReflectionModule.method("filter_by_type_name", 2);
        const FilterTypeName = SystemReflectionModule.field<Il2Cpp.Object>("FilterTypeName").value;
        const FilterTypeNamePointer = FilterTypeName.handle.add(FilterTypeName.class.field("method_ptr").offset).readPointer();

        const source = `\
#include <stdint.h>
#include <string.h>
#include "glib.h"


typedef struct _Il2CppObject Il2CppObject;
typedef enum _Il2CppTypeEnum Il2CppTypeEnum;
typedef struct _Il2CppReflectionMethod Il2CppReflectionMethod;
typedef struct _Il2CppManagedMemorySnapshot Il2CppManagedMemorySnapshot;
typedef struct _Il2CppMetadataType Il2CppMetadataType;


struct _Il2CppObject
{
    void * class;
    void * monitor;
};

enum _Il2CppTypeEnum
{
    IL2CPP_TYPE_END = 0x00,
    IL2CPP_TYPE_VOID = 0x01,
    IL2CPP_TYPE_BOOLEAN = 0x02,
    IL2CPP_TYPE_CHAR = 0x03,
    IL2CPP_TYPE_I1 = 0x04,
    IL2CPP_TYPE_U1 = 0x05,
    IL2CPP_TYPE_I2 = 0x06,
    IL2CPP_TYPE_U2 = 0x07,
    IL2CPP_TYPE_I4 = 0x08,
    IL2CPP_TYPE_U4 = 0x09,
    IL2CPP_TYPE_I8 = 0x0a,
    IL2CPP_TYPE_U8 = 0x0b,
    IL2CPP_TYPE_R4 = 0x0c,
    IL2CPP_TYPE_R8 = 0x0d,
    IL2CPP_TYPE_STRING = 0x0e,
    IL2CPP_TYPE_PTR = 0x0f,
    IL2CPP_TYPE_BYREF = 0x10,
    IL2CPP_TYPE_VALUETYPE = 0x11,
    IL2CPP_TYPE_CLASS = 0x12,
    IL2CPP_TYPE_VAR = 0x13,
    IL2CPP_TYPE_ARRAY = 0x14,
    IL2CPP_TYPE_GENERICINST = 0x15,
    IL2CPP_TYPE_TYPEDBYREF = 0x16,
    IL2CPP_TYPE_I = 0x18,
    IL2CPP_TYPE_U = 0x19,
    IL2CPP_TYPE_FNPTR = 0x1b,
    IL2CPP_TYPE_OBJECT = 0x1c,
    IL2CPP_TYPE_SZARRAY = 0x1d,
    IL2CPP_TYPE_MVAR = 0x1e,
    IL2CPP_TYPE_CMOD_REQD = 0x1f,
    IL2CPP_TYPE_CMOD_OPT = 0x20,
    IL2CPP_TYPE_INTERNAL = 0x21,
    IL2CPP_TYPE_MODIFIER = 0x40,
    IL2CPP_TYPE_SENTINEL = 0x41,
    IL2CPP_TYPE_PINNED = 0x45,
    IL2CPP_TYPE_ENUM = 0x55
};

struct _Il2CppReflectionMethod
{
    Il2CppObject object;
    void * method;
    void * name;
    void * reftype;
};

struct _Il2CppManagedMemorySnapshot
{
    struct Il2CppManagedHeap
    {
        uint32_t section_count;
        void * sections;
    } heap;
    struct Il2CppStacks
    {
        uint32_t stack_count;
        void * stacks;
    } stacks;
    struct Il2CppMetadataSnapshot
    {
        uint32_t type_count;
        Il2CppMetadataType * types;
    } metadata_snapshot;
    struct Il2CppGCHandles
    {
        uint32_t tracked_object_count;
        Il2CppObject ** pointers_to_objects;
    } gc_handles;
    struct Il2CppRuntimeInformation
    {
        uint32_t pointer_size;
        uint32_t object_header_size;
        uint32_t array_header_size;
        uint32_t array_bounds_offset_in_header;
        uint32_t array_size_offset_in_header;
        uint32_t allocation_granularity;
    } runtime_information;
    void * additional_user_information;
};

struct _Il2CppMetadataType
{
    uint32_t flags;
    void * fields;
    uint32_t field_count;
    uint32_t statics_size;
    uint8_t * statics;
    uint32_t base_or_element_type_index;
    char * name;
    const char * assembly_name;
    uint64_t type_info_address;
    uint32_t size;
};


#define THREAD_STATIC_FIELD_OFFSET -1;

#define FIELD_ATTRIBUTE_FIELD_ACCESS_MASK 0x0007
#define FIELD_ATTRIBUTE_COMPILER_CONTROLLED 0x0000
#define FIELD_ATTRIBUTE_PRIVATE 0x0001
#define FIELD_ATTRIBUTE_FAM_AND_ASSEM 0x0002
#define FIELD_ATTRIBUTE_ASSEMBLY 0x0003
#define FIELD_ATTRIBUTE_FAMILY 0x0004
#define FIELD_ATTRIBUTE_FAM_OR_ASSEM 0x0005
#define FIELD_ATTRIBUTE_PUBLIC 0x0006

#define FIELD_ATTRIBUTE_STATIC 0x0010
#define FIELD_ATTRIBUTE_LITERAL 0x0040

#define METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK 0x0007
#define METHOD_ATTRIBUTE_COMPILER_CONTROLLED 0x0000
#define METHOD_ATTRIBUTE_PRIVATE 0x0001
#define METHOD_ATTRIBUTE_FAM_AND_ASSEM 0x0002
#define METHOD_ATTRIBUTE_ASSEMBLY 0x0003
#define METHOD_ATTRIBUTE_FAMILY 0x0004
#define METHOD_ATTRIBUTE_FAM_OR_ASSEM 0x0005
#define METHOD_ATTRIBUTE_PUBLIC 0x0006

#define METHOD_ATTRIBUTE_STATIC 0x0010
#define METHOD_IMPL_ATTRIBUTE_INTERNAL_CALL 0x1000
#define METHOD_IMPL_ATTRIBUTE_SYNCHRONIZED 0x0020


extern char * il2cpp_value_to_string (void *, void *, int *);

const char * (*il2cpp_image_get_name) (void *) = (void *) ${this._imageGetName};
void * (*il2cpp_class_from_type) (void *) = (void *) ${this._classFromType};
void * (*il2cpp_class_get_base_type) (void *) = (void *) ${this._classGetBaseType};
void * (*il2cpp_class_get_declaring_type) (void *) = (void *) ${this._classGetDeclaringType};
uint16_t (*il2cpp_class_get_field_count) (void *) = (void *) ${this._classGetFieldCount};
void * (*il2cpp_class_get_image) (void *) = (void *) ${this._classGetImage};
int32_t (*il2cpp_class_instance_size) (void *) = (void *) ${this._classGetInstanceSize};
void * (*il2cpp_class_get_interfaces) (void *, void **) = (void *) ${this._classGetInterfaces};
void * (*il2cpp_class_get_fields) (void *, void **) = (void *) ${this._classGetFields};
void * (*il2cpp_class_get_methods) (void *, void **) = (void *) ${this._classGetMethods};
const char * (*il2cpp_class_get_name) (void *) = (void *) ${this._classGetName};
void * (*il2cpp_class_get_parent) (void *) = (void *) ${this._classGetParent};
void * (*il2cpp_class_get_type) (void *) = (void *) ${this._classGetType};
uint8_t (*il2cpp_class_is_enum) (void *) = (void *) ${this._classIsEnum};
uint8_t (*il2cpp_class_is_inflated) (void *) = (void *) ${this._classIsInflated};
uint8_t (*il2cpp_class_is_interface) (void *) = (void *) ${this._classIsInterface};
uint8_t (*il2cpp_class_is_generic) (void *) = (void *) ${this._classIsGeneric};
uint8_t (*il2cpp_class_is_valuetype) (void *) = (void *) ${this._classIsValueType};
int (*il2cpp_field_get_flags) (void *) = (void *) ${this._fieldGetFlags};
size_t (*il2cpp_field_get_offset) (void *) = (void *) ${this._fieldGetOffset};
const char * (*il2cpp_field_get_name) (void *) = (void *) ${this._fieldGetName};
void (*il2cpp_field_get_static_value) (void *, void *) = (void *) ${this._fieldGetStaticValue};
void * (*il2cpp_field_get_type) (void *) = (void *) ${this._fieldGetType};
uint32_t (*il2cpp_method_get_flags) (void *, uint32_t *) = (void *) ${this._methodGetFlags};
const char * (*il2cpp_method_get_name) (void *) = (void *) ${this._methodGetName};
int32_t (*il2cpp_method_get_parameter_count) (void *) = (void *) ${this._methodGetParameterCount};
const char * (*il2cpp_method_get_parameter_name) (void *, uint32_t) = (void *) ${this._methodGetParameterName};
void * (*il2cpp_method_get_parameter_type) (void *, uint32_t) = (void *) ${this._methodGetParameterType};
void * (*il2cpp_method_get_return_type) (void *) = (void *) ${this._methodGetReturnType};
uint8_t (*il2cpp_method_is_generic) (void *) = (void *) ${this._methodIsGeneric};
uint8_t (*il2cpp_method_is_inflated) (void *) = (void *) ${this._methodIsInflated};
uint8_t (*il2cpp_method_is_instance) (void *) = (void *) ${this._methodIsInstance};
char * (*il2cpp_type_get_name) (void *) = (void *) ${this._typeGetName};
Il2CppTypeEnum (*il2cpp_type_get_type_enum) (void *) = (void *) ${this._typeGetTypeEnum};
void (*il2cpp_free) (void * pointer) = (void *) ${this._free};


void il2cpp_class_to_string (void *, GString *);

void il2cpp_field_to_string (void *, GString *);

void il2cpp_method_to_string (void *, GString *);


static void
g_string_append_type_name (GString * string,
                           void * type)
{   
    char * type_name;
    
    type_name = il2cpp_type_get_name (type);

    g_string_append (string, type_name);

    il2cpp_free (type_name);
}

const char *
il2cpp_struct_to_string (const void * target,
                         void (*callback) (const void * target, GString * text))
{
    GString * text;
    
    text = g_string_new (NULL);
    
    callback (target, text);

    return g_string_free (text, 0);
}

void
il2cpp_string_set_length (int32_t * string,
                          int32_t length)
{
    *(string + ${offsetOfInt32(Il2Cpp.String.from("vfsfitvnm"), 9)}) = length;
}

void *
il2cpp_array_get_elements (int32_t * array)
{ 
    return array + ${offsetOfInt32(DaysToMonth365, 31) - 1};
}

uint8_t
il2cpp_type_is_byref (void * type)
{   
    char * name;
    char last_char;

    name = il2cpp_type_get_name (type);
    last_char = name[strlen (name) - 1];

    il2cpp_free (name);
    return last_char == '&';
}

uint8_t
il2cpp_type_is_primitive (void * type)
{
    Il2CppTypeEnum type_enum;

    type_enum = il2cpp_type_get_type_enum (type);

    return ((type_enum >= IL2CPP_TYPE_BOOLEAN && 
        type_enum <= IL2CPP_TYPE_R8) || 
        type_enum == IL2CPP_TYPE_I || 
        type_enum == IL2CPP_TYPE_U
    );
}

int32_t
il2cpp_class_get_actual_instance_size (int32_t * class)
{
    return *(class + ${offsetOfInt32(SystemString, SystemString.instanceSize - 2)});
}

uint16_t
il2cpp_class_get_interface_count (uint16_t * class)
{
    return *(class + ${offsetOfUInt16(SystemString, 7)});
}

uint16_t
il2cpp_class_get_method_count (uint16_t * class)
{
    return *(class + ${offsetOfUInt16(SystemValueType, 7)});
}

uint8_t
il2cpp_class_get_rank (void * class)
{
    uint8_t rank;
    const char * name;
    
    rank = 0;
    name = il2cpp_class_get_name (class);

    for (uint16_t i = strlen (name) - 1; i > 0; i--)
    {
        char c = name[i];

        if (c == ']') rank++;
        else if (c == '[' || rank == 0) break;
        else if (c == ',') rank++;
        else break;
    }

    return rank;
}

void
il2cpp_class_to_string (void * class,
                        GString * text)
{
    void * parent;
    uint16_t interface_count;
    uint16_t field_count;
    uint16_t method_count;
    void * iter;

    parent = il2cpp_class_get_parent (class);
    interface_count = il2cpp_class_get_interface_count (class);
    field_count = il2cpp_class_get_field_count (class);
    method_count = il2cpp_class_get_method_count (class);
    iter = NULL;

    g_string_append_len (text, "// ", 3);
    g_string_append (text, il2cpp_image_get_name (il2cpp_class_get_image (class)));
    g_string_append_c (text, '\n');
    
    if (il2cpp_class_is_enum (class))
    {
        g_string_append_len (text, "enum", 4);
    }
    else if (il2cpp_class_is_valuetype (class))
    {
        g_string_append_len (text, "struct", 6);
    }
    else if (il2cpp_class_is_interface (class))
    {
        g_string_append_len (text, "interface", 9);
    }
    else
    {
        g_string_append_len (text, "class", 5);
    }

    g_string_append_c (text, ' ');
    g_string_append_type_name (text, il2cpp_class_get_type (class));

    if (parent != NULL || interface_count > 0)
    {
        g_string_append_len (text, " : ", 3);

        if (parent != NULL)
        {
            g_string_append_type_name (text, il2cpp_class_get_type (parent));
        }

        for (uint16_t i = 0; i < interface_count; i++)
        {   
            if (i > 0 || parent != NULL)
            {
                g_string_append_len (text, ", ", 2);
            }

            g_string_append_type_name (text, il2cpp_class_get_type (il2cpp_class_get_interfaces (class, &iter)));
        }
    }

    g_string_append_len (text, "\n{", 2);
    
    iter = NULL;
    for (uint16_t i = 0;  i < field_count; i++)
    {   
        g_string_append_len (text, "\n    ", 5);
        il2cpp_field_to_string (il2cpp_class_get_fields (class, &iter), text);
    }

    if (field_count > 0 && method_count > 0)
    {
        g_string_append_c (text, '\n');
    }

    iter = NULL;
    for (uint16_t i = 0; i < method_count; i++)
    {   
        g_string_append_len (text, "\n    ", 5);
        il2cpp_method_to_string (il2cpp_class_get_methods (class, &iter), text);
    }

    g_string_append_len (text, "\n}\n\n", 4);
}

const char *
il2cpp_field_get_modifier (void * field)
{   
    int flags;

    flags = il2cpp_field_get_flags (field);

    switch (flags & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK) {
        case FIELD_ATTRIBUTE_PRIVATE:
            return "private";
        case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
            return "private protected";
        case FIELD_ATTRIBUTE_ASSEMBLY:
            return "internal";
        case FIELD_ATTRIBUTE_FAMILY:
            return "protected";
        case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
            return "protected internal";
        case FIELD_ATTRIBUTE_PUBLIC:
            return "public";
    }

    return "";
}

uint8_t
il2cpp_field_is_literal (void * field)
{
    return (il2cpp_field_get_flags (field) & FIELD_ATTRIBUTE_LITERAL) != 0;
}

uint8_t
il2cpp_field_is_static (void * field)
{
    return (il2cpp_field_get_flags (field) & FIELD_ATTRIBUTE_STATIC) != 0;
}

uint8_t
il2cpp_field_is_thread_static (void * field)
{
    return il2cpp_field_get_offset (field) == THREAD_STATIC_FIELD_OFFSET;
}

void
il2cpp_field_to_string (void * field,
                        GString * text)
{
    void * value;
    void * type;
    void * class;
    uint8_t has_offset;

    has_offset = 1;
    type = il2cpp_field_get_type (field);

    if (il2cpp_field_is_thread_static (field))
    {   
        has_offset = 0;

        g_string_append_len (text, "[ThreadStatic] ", 15);
    }

    if (il2cpp_field_is_static (field))
    {
        g_string_append_len (text, "static ", 7);
    }

    g_string_append_type_name (text, type);
    g_string_append_c (text, ' ');
    g_string_append (text, il2cpp_field_get_name (field));

    if (il2cpp_field_is_literal (field))
    {
        char * buf;
        int size;

        has_offset = 0;

        value = g_malloc (sizeof (void *));
        class = il2cpp_class_from_type (type);

        il2cpp_field_get_static_value (field, value);

        g_string_append_len (text, " = ", 3);

        if (il2cpp_class_is_enum (class))
          type = il2cpp_class_get_base_type (class);

        buf = il2cpp_value_to_string (value, type, &size);

        g_string_append_len (text, buf, size);

        g_free (value);
        il2cpp_free (buf);
    }

    g_string_append_c (text, ';');

    if (has_offset)
    {
        g_string_append_printf (text, " // 0x%x", il2cpp_field_get_offset (field));
    }
}

const char *
il2cpp_method_get_modifier (void * method)
{
    uint32_t flags;

    flags = il2cpp_method_get_flags (method, NULL);

    switch (flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) {
        case METHOD_ATTRIBUTE_PRIVATE:
            return "private";
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            return "private protected";
        case METHOD_ATTRIBUTE_ASSEMBLY:
            return "internal";
        case METHOD_ATTRIBUTE_FAMILY:
            return "protected";
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            return "protected internal";
        case METHOD_ATTRIBUTE_PUBLIC:
            return "public";
    }

    return "";
}

void *
il2cpp_method_get_from_reflection (const Il2CppReflectionMethod * method)
{
    return method->method;
}

void *
il2cpp_method_get_pointer (void ** method)
{
    return * (method + ${offsetOfPointer(filter_by_type_name, FilterTypeNamePointer)});
}

uint8_t
il2cpp_method_is_external (void * method)
{
    uint32_t implementation_flags;

    il2cpp_method_get_flags (method, &implementation_flags);

    return (implementation_flags & METHOD_IMPL_ATTRIBUTE_INTERNAL_CALL) != 0;
}

uint8_t
il2cpp_method_is_synchronized (void * method)
{
    uint32_t implementation_flags;

    il2cpp_method_get_flags (method, &implementation_flags);

    return (implementation_flags & METHOD_IMPL_ATTRIBUTE_SYNCHRONIZED) != 0;
}

void
il2cpp_method_to_string (void * method,
                         GString * text)
{    
    int32_t parameter_count;
    void * pointer;

    parameter_count = il2cpp_method_get_parameter_count (method);
    pointer = il2cpp_method_get_pointer ((void **) method);

    if (!il2cpp_method_is_instance (method))
    {
        g_string_append_len (text, "static ", 7);
    }

    g_string_append_type_name (text, il2cpp_method_get_return_type (method));
    g_string_append_c (text, ' ');
    g_string_append (text, il2cpp_method_get_name (method));
    g_string_append_c (text, '(');

    for (uint32_t i = 0; i < parameter_count; i++)
    {
        const char * param_name;

        if (i > 0) g_string_append_len (text, ", ", 2);
        
        g_string_append_type_name (text, il2cpp_method_get_parameter_type (method, i));
        g_string_append_c (text, ' ');

        param_name = il2cpp_method_get_parameter_name (method, i);

        g_string_append (text, param_name == NULL ? "" : param_name);
    }

    g_string_append_len (text, ");", 2);

    if (pointer != NULL)
    {
        g_string_append_printf (text, " // 0x%.8x", GPOINTER_TO_INT (pointer) - ${Il2Cpp.module.base});
    }
}

uintptr_t
il2cpp_memory_snapshot_get_classes (const Il2CppManagedMemorySnapshot * snapshot,
                                    Il2CppMetadataType ** iter)
{
    const int zero;
    const void * null;

    if (iter != NULL && snapshot->metadata_snapshot.type_count > zero)
    {
        if (*iter == null)
        {
            *iter = snapshot->metadata_snapshot.types;
            return (uintptr_t) (*iter)->type_info_address;
        }
        else
        {
            Il2CppMetadataType * metadata_type = *iter + 1;

            if (metadata_type < snapshot->metadata_snapshot.types + snapshot->metadata_snapshot.type_count)
            {
                *iter = metadata_type;
                return (uintptr_t) (*iter)->type_info_address;
            }
        }
    }
    return 0;
}

struct Il2CppGCHandles
il2cpp_memory_snapshot_get_gc_handles (const Il2CppManagedMemorySnapshot * snapshot)
{
    return snapshot->gc_handles;
}

struct Il2CppRuntimeInformation
il2cpp_memory_snapshot_get_information (const Il2CppManagedMemorySnapshot * snapshot)
{
    return snapshot->runtime_information;
}
        `;

        offsetsFinderCModule.dispose();

        return new CModule(source, {
            il2cpp_value_to_string: new NativeCallback(
                (value: NativePointer, type: NativePointer, size: NativePointer): NativePointer => {
                    const string = read(value, new Il2Cpp.Type(type)).toString();
                    size.writeInt(string.length);
                    return Il2Cpp.alloc(string.length + 1).writeUtf8String(string);
                },
                "pointer",
                ["pointer", "pointer", "pointer"]
            )
        });
    }

    /** @internal */
    private static r<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(
        exportName: string,
        retType: RetType,
        argTypes: ArgTypes,
        requiredUnityVersion?: string
    ) {
        const exportPointer = Il2Cpp.module.findExportByName(exportName) || this.cModule[exportName];

        if (exportPointer == null) {
            if (requiredUnityVersion == null || Unity.version.isEqualOrAbove(requiredUnityVersion)) {
                raise(`cannot resolve export ${exportName}`);
            }

            raise(`${exportName} was added in version ${requiredUnityVersion}, but this application uses ${Unity.version}`);
        }

        return new NativeFunction(exportPointer, retType, argTypes);
    }
}

Il2Cpp.Api = Il2CppApi;

declare global {
    namespace Il2Cpp {
        class Api extends Il2CppApi {}
    }
}
