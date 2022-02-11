import { cache } from "decorator-cache-getter";
import Versioning from "versioning";
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
        return this.r("il2cpp_class_for_each", "void", ["pointer", "pointer"]);
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
    static get _classGetInterfaces() {
        return this.r("il2cpp_class_get_interfaces", "pointer", ["pointer", "pointer"]);
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
        return this.r("il2cpp_class_get_static_field_data", "pointer", ["pointer"]);
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
        return this.r("il2cpp_class_is_blittable", "bool", ["pointer"]);
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
    static get _free() {
        return this.r("il2cpp_free", "void", ["pointer"]);
    }

    @cache
    static get _gcCollect() {
        return this.r("il2cpp_gc_collect", "void", ["int"]);
    }

    @cache
    static get _gcCollectALittle() {
        return this.r("il2cpp_gc_collect_a_little", "void", []);
    }

    @cache
    static get _gcDisable() {
        return this.r("il2cpp_gc_disable", "void", []);
    }

    @cache
    static get _gcEnable() {
        return this.r("il2cpp_gc_enable", "void", []);
    }

    @cache
    static get _gcGetHeapSize() {
        return this.r("il2cpp_gc_get_heap_size", "int64", []);
    }

    @cache
    static get _gcGetMaxTimeSlice() {
        return this.r("il2cpp_gc_get_max_time_slice_ns", "int64", []);
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
        return this.r("il2cpp_gc_is_disabled", "bool", []);
    }

    @cache
    static get _gcIsIncremental() {
        return this.r("il2cpp_gc_is_incremental", "bool", []);
    }

    @cache
    static get _gcSetMaxTimeSlice() {
        return this.r("il2cpp_gc_set_max_time_slice_ns", "void", ["int64"]);
    }

    @cache
    static get _gcStartIncrementalCollection() {
        return this.r("il2cpp_gc_start_incremental_collection", "void", []);
    }

    @cache
    static get _gcStartWorld() {
        return this.r("il2cpp_start_gc_world", "void", []);
    }

    @cache
    static get _gcStopWorld() {
        return this.r("il2cpp_stop_gc_world", "void", []);
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
        return this.r("il2cpp_image_get_class_count", "uint32", ["pointer"]);
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
    static get _livenessAllocateStruct() {
        return this.r("il2cpp_unity_liveness_allocate_struct", "pointer", ["pointer", "int", "pointer", "pointer", "pointer"]);
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
    static get _livenessFinalize() {
        return this.r("il2cpp_unity_liveness_finalize", "void", ["pointer"]);
    }

    @cache
    static get _livenessFreeStruct() {
        return this.r("il2cpp_unity_liveness_free_struct", "void", ["pointer"]);
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
    static get _resolveInternalCall() {
        return this.r("il2cpp_resolve_icall", "pointer", ["pointer"]);
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
        if (Versioning.lt(Il2Cpp.unityVersion, "5.3.0") || Versioning.gte(Il2Cpp.unityVersion, "2022.2.0")) {
            warn(`current Unity version ${Il2Cpp.unityVersion} is not supported, expect breakage`);
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

OFFSET_OF (offset_of_int32, int32_t)
OFFSET_OF (offset_of_pointer, void *)
            `);

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

        const source = `\
#include <stdint.h>
#include <string.h>


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


static const char * (*il2cpp_class_get_name) (void *) = (void *) ${this._classGetName};
static int (*il2cpp_field_get_flags) (void *) = (void *) ${this._fieldGetFlags};
static size_t (*il2cpp_field_get_offset) (void *) = (void *) ${this._fieldGetOffset};
static uint32_t (*il2cpp_method_get_flags) (void *, uint32_t *) = (void *) ${this._methodGetFlags};
static char * (*il2cpp_type_get_name) (void *) = (void *) ${this._typeGetName};
static Il2CppTypeEnum (*il2cpp_type_get_type_enum) (void *) = (void *) ${this._typeGetTypeEnum};
static void (*il2cpp_free) (void * pointer) = (void *) ${this._free};


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
    return * (method + ${offsetOfPointer(FilterTypeNameMethod, FilterTypeNameMethodPointer)});
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

        return new CModule(source);
    }

    /** @internal */
    private static r<R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(
        exportName: string,
        retType: R,
        argTypes: A
    ) {
        const exportPointer = Il2Cpp.module.findExportByName(exportName) ?? this.cModule[exportName];

        if (exportPointer == null) {
            raise(`cannot resolve export ${exportName}`);
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
