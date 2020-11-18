import { resolve, sources } from "./utils/api-factory";
import { inform, ok, raise } from "./utils/console";
import UnityVersion from "./utils/unity-version";
import { forLibrary, il2CppLibraryName, unityLibraryName } from "./utils/platform";
import Il2CppDomain from "./il2cpp/domain";
import Il2CppObject from "./il2cpp/object";
import Il2CppString from "./il2cpp/string";
import Il2CppArray from "./il2cpp/array";
import Il2CppTypeEnum from "./il2cpp/type-enum";
import GC from "./il2cpp/gc";
import { choose } from "./il2cpp/runtime";

/** @internal */
function getMissingExports() {
    return new CModule(`
#include "stdint.h"
#include "glib.h"
#include "string.h"
#include "stdio.h"

#define TYPE_ATTRIBUTE_INTERFACE 0x00000020

#define FIELD_ATTRIBUTE_STATIC 0x0010
#define FIELD_ATTRIBUTE_LITERAL 0x0040

#define METHOD_ATTRIBUTE_STATIC 0x0010

typedef struct _Il2CppObject Il2CppObject;
typedef struct _Il2CppString Il2CppString;
typedef struct _Il2CppArray Il2CppArray;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.3")}
typedef struct _Il2CppArraySize Il2CppArraySize;
#endif
typedef struct _Il2CppDomain Il2CppDomain;
typedef struct _Il2CppAssemblyName Il2CppAssemblyName;
typedef struct _Il2CppAssembly Il2CppAssembly;
typedef struct _Il2CppImage Il2CppImage;
typedef struct _Il2CppClass Il2CppClass;
typedef struct _Il2CppType Il2CppType;
typedef struct _FieldInfo FieldInfo;
typedef struct _MethodInfo MethodInfo;
typedef struct _ParameterInfo ParameterInfo;
typedef enum _Il2CppTypeEnum Il2CppTypeEnum;
typedef struct _VirtualInvokeData VirtualInvokeData;
typedef struct _Il2CppGenericInst Il2CppGenericInst;
typedef struct _Il2CppGenericClass Il2CppGenericClass;
typedef struct _Il2CppGenericContext Il2CppGenericContext;
typedef uint16_t Il2CppChar;

static const uint64_t IL2CPP_BASE = ${Process.getModuleByName(il2CppLibraryName!).base};

const char * (* il2cpp_type_get_name) (const Il2CppType * type) = GUINT_TO_POINTER (${resolve("il2cpp_type_get_name")});

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

struct _Il2CppObject
{
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    union
    {
        Il2CppClass * klass;
        struct Il2CppVTable * vtable;
    };
#else
    Il2CppClass * klass;
#endif
    struct MonitorData * monitor;
};

#if ${+UnityVersion.CURRENT.isBelow("2019.3.0")}
size_t
il2cpp_object_header_size (void)
{
    return sizeof (Il2CppObject);
}
#endif

struct _Il2CppDomain
{
    struct Il2CppAppDomain * domain;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.5.0")}
    struct Il2CppAppDomainSetup * setup;
#else
    Il2CppObject * setup;
#endif
    struct Il2CppAppContext * default_context;
    const char * friendly_name;
    uint32_t domain_id;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.5.0")}
    volatile int threadpool_jobs;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    void * agent_info;
#endif
};

const char *
il2cpp_domain_get_name (const Il2CppDomain* domain)
{
    return domain->friendly_name;
}

struct _Il2CppAssemblyName
{
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    const char * name;
    const char * culture;
    const char * hash_value;
    const char * public_key;
#else
    int32_t nameIndex;
    int32_t cultureIndex;
    int32_t hashValueIndex;
    int32_t publicKeyIndex;
#endif
    uint32_t hash_alg;
    int32_t hash_len;
    uint32_t flags;
    int32_t major;
    int32_t minor;
    int32_t build;
    int32_t revision;
    uint8_t publicKeyToken[8];
};

struct _Il2CppAssembly
{
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    Il2CppImage * image;
#else
    int32_t imageIndex;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.3.0")}
    uint32_t token;
#else
    int32_t customAttributeIndex;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.3")}
    int32_t referencedAssemblyStart;
    int32_t referencedAssemblyCount;
#endif
    Il2CppAssemblyName aname;
};

#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
const char *
il2cpp_assembly_get_name (const Il2CppAssembly * assembly)
{
    return assembly->aname.name;
}
#endif

struct _Il2CppImage
{
    const char * name;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2017.1.3") && +!UnityVersion.CURRENT.isEqual("2017.2.0")}
    const char * nameNoExt;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    Il2CppAssembly * assembly;
#else
    int32_t assemblyIndex;
#endif
#if ${+UnityVersion.CURRENT.isBelow("2020.2.0")}
    int32_t typeStart;
#endif
    uint32_t typeCount;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2017.1.0")}
#if ${+UnityVersion.CURRENT.isBelow("2020.2.0")}
    int32_t exportedTypeStart;
#endif
    uint32_t exportedTypeCount;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.3.0")}
#if ${+UnityVersion.CURRENT.isBelow("2020.2.0")}
    int32_t customAttributeStart;
#endif
    uint32_t customAttributeCount;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
    const struct Il2CppMetadataImageHandle * metadataHandle;
    struct Il2CppNameToTypeHandleHashTable * nameToClassHashTable;
#else
    int32_t entryPointIndex;
    struct Il2CppNameToTypeDefinitionIndexHashTable * nameToClassHashTable;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2019.1.0")}
    const struct Il2CppCodeGenModule * codeGenModule;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.2")}
    uint32_t token;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    uint8_t dynamic;
#endif
};

#if ${+UnityVersion.CURRENT.isBelow("2020.2.0")}
uint32_t
il2cpp_image_get_class_start (const Il2CppImage * image)
{
    return image->typeStart;
}
#endif

#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
uint32_t
il2cpp_image_get_class_count (const Il2CppImage * image)
{
    return image->typeCount;
}
#endif

struct _Il2CppType
{
    union
    {
        void * dummy;
        int32_t klassIndex;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
        const struct Il2CppMetadataTypeHandle * typeHandle;
#endif
        const Il2CppType * type;
        struct Il2CppArrayType * array;
        int32_t genericParameterIndex;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
        const struct Il2CppMetadataGenericParameterHandle * genericParameterHandle;
#endif
        Il2CppGenericClass * generic_class;
    } data;
    unsigned int attrs: 16;
    Il2CppTypeEnum type: 8;
    unsigned int num_mods: 6;
    unsigned int byref: 1;
    unsigned int pinned: 1;
};

uint16_t
il2cpp_type_offset_of_type (void)
{
    return (uint16_t) offsetof (Il2CppType, type);
}

const Il2CppType *
il2cpp_type_get_data_type (const Il2CppType * type)
{
    return type->data.type;
}

Il2CppGenericClass *
il2cpp_type_get_generic_class (const Il2CppType * type)
{
    return type->data.generic_class;
}

#if ${+UnityVersion.CURRENT.isBelow("2018.1.0")}
unsigned int
il2cpp_type_is_byref (const Il2CppType * type)
{
    return type->byref;
}
#endif

struct _VirtualInvokeData
{
    void * methodPtr;
    const MethodInfo * method;
};

struct _Il2CppClass
{
    const Il2CppImage * image;
    void* gc_desc;
    const char * name;
    const char * namespaze;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    Il2CppType byval_arg;
    Il2CppType this_arg;
#else
    const Il2CppType* byval_arg;
    const Il2CppType* this_arg;
#endif
    Il2CppClass * element_class;
    Il2CppClass * castClass;
    Il2CppClass * declaringType;
    Il2CppClass * parent;
    Il2CppGenericClass * generic_class;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
    const struct Il2CppMetadataTypeHandle * typeMetadataHandle;
#else
    const struct Il2CppTypeDefinition * typeDefinition;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.6.0")}
    const struct Il2CppInteropData * interopData;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    Il2CppClass * klass;
#endif
    FieldInfo * fields;
    const struct EventInfo* events;
    const struct PropertyInfo * properties;
    const MethodInfo ** methods;
    Il2CppClass ** nestedTypes;
    Il2CppClass ** implementedInterfaces;
#if ${+UnityVersion.CURRENT.isBetween("5.3.6", "5.5.0")}
    VirtualInvokeData * vtable;
#endif
#if ${+UnityVersion.CURRENT.isBelow("5.3.6")}
    const MethodInfo ** vtable;
#endif
    struct Il2CppRuntimeInterfaceOffsetPair * interfaceOffsets;
    void * static_fields;
    const struct Il2CppRGCTXData * rgctx_data;
    Il2CppClass ** typeHierarchy;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2019.1.0")}
    void * unity_user_data;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.2.0")}
    uint32_t initializationExceptionGCHandle;
#endif
    uint32_t cctor_started;
    uint32_t cctor_finished;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2019.1.0")}
    __attribute__((aligned(8))) size_t cctor_thread;
#else
    __attribute__((aligned(8))) uint64_t cctor_thread;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
    const struct Il2CppMetadataGenericContainerHandle * genericContainerHandle;
#else
    int32_t genericContainerIndex;
#endif
#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
    int32_t customAttributeIndex;
#endif
    uint32_t instance_size;
    uint32_t actualSize;
    uint32_t element_size;
    int32_t native_size;
    uint32_t static_fields_size;
    uint32_t thread_static_fields_size;
    int32_t thread_static_fields_offset;
    uint32_t flags;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.2")}
    uint32_t token;
#endif
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint8_t typeHierarchyDepth;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.4.4") && +!UnityVersion.CURRENT.isEqual("5.5.0")}
    uint8_t genericRecursionDepth;
#endif
    uint8_t rank;
    uint8_t minimumAlignment;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.3.8")}
    uint8_t naturalAligment;
#endif
    uint8_t packingSize;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.3.0")}
    uint8_t initialized_and_no_error: 1;
#endif
    uint8_t valuetype: 1;
    uint8_t initialized: 1;
    uint8_t enumtype: 1;
    uint8_t is_generic: 1;
    uint8_t has_references: 1;
    uint8_t init_pending: 1;
    uint8_t size_inited: 1;
    uint8_t has_finalize: 1;
    uint8_t has_cctor: 1;
    uint8_t is_blittable: 1;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.3")}
    uint8_t is_import_or_windows_runtime: 1;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.5.0")}
    uint8_t is_vtable_initialized: 1;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.2.0")}
    uint8_t has_initialization_error: 1;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.5.0")}
    VirtualInvokeData vtable[32];
#endif
};

uint16_t
il2cpp_class_get_method_count (const Il2CppClass * klass)
{
    return klass->method_count;
}

uint16_t
il2cpp_class_get_field_count (const Il2CppClass * klass)
{
    return klass->field_count;
}

uint8_t
il2cpp_class_has_static_constructor (const Il2CppClass * klass)
{
    return klass->has_cctor;
}

uint32_t
il2cpp_class_is_static_constructor_finished (const Il2CppClass * klass)
{
    return klass->cctor_finished;
}

#if ${+UnityVersion.CURRENT.isBelow("2019.3.0")}
void *
il2cpp_class_get_static_field_data (const Il2CppClass * klass)
{
    return klass->static_fields;
}
#endif

struct _Il2CppGenericInst
{
    uint32_t type_argc;
    const Il2CppType ** type_argv;
};

struct _Il2CppGenericContext
{
    const Il2CppGenericInst * class_inst;
    const Il2CppGenericInst * method_inst;
};

struct _Il2CppGenericClass
{
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
    const Il2CppType * type;
#else
    int32_t typeDefinitionIndex;
#endif
    Il2CppGenericContext context;
    Il2CppClass * cached_class;
};

Il2CppClass *
il2cpp_generic_class_get_cached_class (Il2CppGenericClass * class)
{
    return class->cached_class;
}

uint32_t
il2cpp_generic_class_get_types_count (Il2CppGenericClass * class)
{
    return class->context.class_inst->type_argc;
}

const Il2CppType **
il2cpp_generic_class_get_types (Il2CppGenericClass * class)
{
    return class->context.class_inst->type_argv;
}

struct _FieldInfo
{
    const char * name;
    const Il2CppType * type;
    Il2CppClass * parent;
    int32_t offset;
#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
    int32_t customAttributeIndex;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.2")}
    uint32_t token;
#endif
};

uint8_t
il2cpp_field_is_instance (FieldInfo * field)
{
    return (field->type->attrs & FIELD_ATTRIBUTE_STATIC) == 0;
}

#if ${+UnityVersion.CURRENT.isBelow("2019.3.0")}
uint8_t
il2cpp_field_is_literal (FieldInfo * field)
{
    return (field->type->attrs & FIELD_ATTRIBUTE_LITERAL) == 0;
}
#endif

struct _ParameterInfo
{
    const char * name;
    int32_t position;
    uint32_t token;
#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
    int32_t customAttributeIndex;
#endif
    const Il2CppType * parameter_type;
};

const char *
il2cpp_parameter_get_name(const ParameterInfo * parameter)
{
    return parameter->name;
}

const Il2CppType *
il2cpp_parameter_get_type (const ParameterInfo * parameter)
{
    return parameter->parameter_type;
}

int32_t
il2cpp_parameter_get_position (const ParameterInfo * parameter)
{
    return parameter->position;
}

struct _MethodInfo
{
    void * methodPointer;
    void * invoker_method;
    const char * name;
    Il2CppClass * klass;
    const Il2CppType * return_type;
    const ParameterInfo * parameters;
    union
    {
        const struct Il2CppRGCTXData * rgctx_data;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
        const struct Il2CppMetadataMethodDefinitionHandle * methodMetadataHandle;
#else
        const struct Il2CppMethodDefinition * methodDefinition;
#endif
    };
    union
    {
        const struct Il2CppGenericMethod * genericMethod;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
        const struct Il2CppMetadataGenericContainer nHandle * genericContainerHandle;
#else
        const struct Il2CppGenericContainer * genericContainer;
#endif
    };
#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
    int32_t customAttributeIndex;
#endif
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t is_generic: 1;
    uint8_t is_inflated: 1;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    uint8_t wrapper_type: 1;
    uint8_t is_marshaled_from_native: 1;
#endif
};

void *
il2cpp_method_get_pointer(const MethodInfo * method)
{
    return method->methodPointer;
}

const ParameterInfo *
il2cpp_method_get_parameters (const MethodInfo * method,
                              void ** iter)
{   
    uint16_t parameters_count = method->parameters_count;
    
    if (iter != 0 && parameters_count > 0)
    {
        void* temp = *iter;
        if (temp == 0)
        {
            *iter = (void**) method->parameters;
            return method->parameters;
        }
        else
        {
            const ParameterInfo * parameterInfo = (ParameterInfo*) *iter + 1;
            if (parameterInfo < method->parameters + parameters_count)
            {
                *iter = (void*) parameterInfo;
                return parameterInfo;
            }
        }
    }
    return 0;
}


struct _Il2CppString
{
    Il2CppObject object;
    int32_t length;
    Il2CppChar chars[32];
};

void
il2cpp_string_set_length (Il2CppString * string,
                          int32_t length)
{
    string->length = length;
}

struct _Il2CppArray
{
    Il2CppObject obj;
    struct Il2CppArrayBounds * bounds;
    uint32_t max_length;
#if ${+UnityVersion.CURRENT.isBelow("5.3.3")}
    double vector[32];
#endif
};

#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.3")}
struct _Il2CppArraySize
{
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    Il2CppObject obj;
    struct Il2CppArrayBounds * bounds;
    uint32_t max_length;
    __attribute__((aligned(8))) void * vector[32];
#else
    Il2CppArray Array;
    __attribute__((aligned(8))) void * vector;
#endif
};
#endif

#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.3")}
void *
il2cpp_array_elements (Il2CppArraySize * array) {
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    return array->vector;
#else
    return &array->vector;
#endif
}
#else
void *
il2cpp_array_elements (Il2CppArray * array) {
    return (void*) array->vector;
}
#endif

const gchar *
il2cpp_class_to_string (const Il2CppClass * klass)
{
    GString * text;

    text = g_string_new (NULL);

    g_string_append_printf (text, "// %s\\n", klass->image->name);
    
    uint8_t is_enum = klass->enumtype;
    uint8_t is_valuetype = klass->valuetype;
    uint8_t is_interface = klass->flags & TYPE_ATTRIBUTE_INTERFACE;
    
    if (is_enum) g_string_append_len (text, "enum ", 5);
    else if (is_valuetype) g_string_append_len (text, "struct ", 7);
    else if (is_interface) g_string_append_len (text, "interface ", 10);
    else g_string_append_len (text, "class ", 6);

#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    g_string_append (text, il2cpp_type_get_name (&klass->byval_arg));
#else
    g_string_append (text, il2cpp_type_get_name (klass->byval_arg));
#endif
    
    g_string_append_len (text, "\\n{", 2);
        
    uint16_t field_count = klass->field_count;
    if (field_count > 0)
    {
        FieldInfo * field;
        for (uint16_t i = 0; i < field_count; i++)
        {
            field = klass->fields + i;
            g_string_append_len (text, "\\n\\t", 2);

            if (is_enum && i > 0)
            {
                g_string_append (text, field->name);
                g_string_append_c (text, ',');
            } else
            {
                if (!il2cpp_field_is_instance (field)) g_string_append_len (text, "static ", 7);
                g_string_append_printf (text, "%s %s; // 0x%x", il2cpp_type_get_name (field->type), field->name, field->offset);
            }
        }
    }

    uint16_t method_count = klass->method_count;
    if (method_count > 0)
    {
        const MethodInfo * method;

        g_string_append_c (text, '\\n');
        for (uint16_t i = 0; i < method_count; i++)
        {
            method = klass->methods[i];
            g_string_append_len (text, "\\n\\t", 2);
            
            uint8_t is_static_flag = method->flags & METHOD_ATTRIBUTE_STATIC;
            
            if (is_static_flag != 0) g_string_append_len (text, "static ", 7);
            g_string_append_printf (text, "%s %s(", il2cpp_type_get_name (method->return_type), method->name);

            const ParameterInfo * param;

            uint16_t parameters_count = method->parameters_count;
            for (uint8_t j = 0; j < parameters_count; j++)
            {
                param = method->parameters + j;
                if (j > 0) g_string_append_len (text, ", ", 2);
                g_string_append_printf (text, "%s %s", il2cpp_type_get_name (param->parameter_type), param->name);
            }

            g_string_append_len (text, ");", 2);
            void * method_pointer = method->methodPointer;
            if (method_pointer != NULL) g_string_append_printf (text, " // 0x%.8x", GPOINTER_TO_INT (method->methodPointer) - IL2CPP_BASE);
        }
    }

    g_string_append_len (text, "\\n}\\n\\n", 4);

    return g_string_free (text, 0);
}
`);
}

(global as any).Il2Cpp = {
    Domain: Il2CppDomain,
    Object: Il2CppObject,
    String: Il2CppString,
    Array: Il2CppArray,
    TypeEnum: Il2CppTypeEnum,

    GC: GC,

    choose: choose,

    async initialize() {
        if (Process.platform != "linux") {
            raise(`Platform "${Process.platform}" is not supported yet.`);
        }

        await forLibrary(unityLibraryName!);
        await forLibrary(il2CppLibraryName!);

        this.unityVersion = UnityVersion.CURRENT.toString();

        if (!UnityVersion.CURRENT.isValid || !UnityVersion.CURRENT.isSupported) {
            raise(`Unity version "${UnityVersion.CURRENT}" is not valid or supported.`);
        }

        sources.push(Process.getModuleByName(il2CppLibraryName!));
        sources.push(getMissingExports());
    },

    async dump(filename: string) {
        const domain = (await this.Domain.get()) as Il2CppDomain;

        inform("Dumping...");

        const content = Array.from(domain.assemblies)
            .map(assembly => Array.from(assembly.image.classes).join(""))
            .join("\n");

        const file = new File(filename, "w");
        file.write(content);
        file.flush();
        file.close();
        ok(`Dump saved to ${filename}.`);
    }
};
