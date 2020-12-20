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
import { choose, choose2 } from "./il2cpp/runtime";

/** @internal */
function getMissingExports() {
    return new CModule(`
#include "glib.h"

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
typedef gunichar2 Il2CppChar;
typedef struct _Il2CppManagedMemorySnapshot Il2CppManagedMemorySnapshot;
typedef struct _Il2CppMetadataSnapshot Il2CppMetadataSnapshot;
typedef struct _Il2CppManagedMemorySection Il2CppManagedMemorySection;
typedef struct _Il2CppManagedHeap Il2CppManagedHeap;
typedef struct _Il2CppStacks Il2CppStacks;
typedef struct _Il2CppGCHandles Il2CppGCHandles;
typedef struct _Il2CppRuntimeInformation Il2CppRuntimeInformation;

static const guint64 IL2CPP_BASE = ${Process.getModuleByName(il2CppLibraryName!).base};

const gchar * (* il2cpp_type_get_name) (const Il2CppType * type) = GUINT_TO_POINTER (${resolve("il2cpp_type_get_name")});

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
    const gchar * friendly_name;
    guint32 domain_id;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.5.0")}
    volatile gint threadpool_jobs;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    gpointer agent_info;
#endif
};

const gchar *
il2cpp_domain_get_name (const Il2CppDomain* domain)
{
    return domain->friendly_name;
}

struct _Il2CppAssemblyName
{
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    const gchar * name;
    const gchar * culture;
    const gchar * hash_value;
    const gchar * public_key;
#else
    gint32 nameIndex;
    gint32 cultureIndex;
    gint32 hashValueIndex;
    gint32 publicKeyIndex;
#endif
    guint32 hash_alg;
    gint32 hash_len;
    guint32 flags;
    gint32 major;
    gint32 minor;
    gint32 build;
    gint32 revision;
    guint8 publicKeyToken[8];
};

struct _Il2CppAssembly
{
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    Il2CppImage * image;
#else
    gint32 imageIndex;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.3.0")}
    guint32 token;
#else
    gint32 customAttributeIndex;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.3")}
    gint32 referencedAssemblyStart;
    gint32 referencedAssemblyCount;
#endif
    Il2CppAssemblyName aname;
};

#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
const gchar *
il2cpp_assembly_get_name (const Il2CppAssembly * assembly)
{
    return assembly->aname.name;
}
#endif

struct _Il2CppImage
{
    const gchar * name;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2017.1.3") && +!UnityVersion.CURRENT.isEqual("2017.2.0")}
    const gchar * nameNoExt;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    Il2CppAssembly * assembly;
#else
    gint32 assemblyIndex;
#endif
#if ${+UnityVersion.CURRENT.isBelow("2020.2.0")}
    gint32 typeStart;
#endif
    guint32 typeCount;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2017.1.0")}
#if ${+UnityVersion.CURRENT.isBelow("2020.2.0")}
    gint32 exportedTypeStart;
#endif
    guint32 exportedTypeCount;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.3.0")}
#if ${+UnityVersion.CURRENT.isBelow("2020.2.0")}
    gint32 customAttributeStart;
#endif
    guint32 customAttributeCount;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
    const struct Il2CppMetadataImageHandle * metadataHandle;
    struct Il2CppNameToTypeHandleHashTable * nameToClassHashTable;
#else
    gint32 entryPointIndex;
    struct Il2CppNameToTypeDefinitionIndexHashTable * nameToClassHashTable;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2019.1.0")}
    const struct Il2CppCodeGenModule * codeGenModule;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.2")}
    guint32 token;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    guint8 dynamic;
#endif
};

#if ${+UnityVersion.CURRENT.isBelow("2020.2.0")}
guint32
il2cpp_image_get_class_start (const Il2CppImage * image)
{
    return image->typeStart;
}
#endif

#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
guint32
il2cpp_image_get_class_count (const Il2CppImage * image)
{
    return image->typeCount;
}
#endif

struct _Il2CppType
{
    union
    {
        gpointer dummy;
        gint32 klassIndex;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
        const struct Il2CppMetadataTypeHandle * typeHandle;
#endif
        const Il2CppType * type;
        struct Il2CppArrayType * array;
        gint32 genericParameterIndex;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
        const struct Il2CppMetadataGenericParameterHandle * genericParameterHandle;
#endif
        Il2CppGenericClass * generic_class;
    } data;
    guint attrs: 16;
    Il2CppTypeEnum type: 8;
    guint num_mods: 6;
    guint byref: 1;
    guint pinned: 1;
};

guint16
il2cpp_type_offset_of_type (void)
{
    return (guint16) offsetof (Il2CppType, type);
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
guint
il2cpp_type_is_byref (const Il2CppType * type)
{
    return type->byref;
}
#endif

struct _VirtualInvokeData
{
    gpointer methodPtr;
    const MethodInfo * method;
};

struct _Il2CppClass
{
    const Il2CppImage * image;
    gpointer gc_desc;
    const gchar * name;
    const gchar * namespaze;
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
    gpointer static_fields;
    const struct Il2CppRGCTXData * rgctx_data;
    Il2CppClass ** typeHierarchy;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2019.1.0")}
    gpointer unity_user_data;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.2.0")}
    guint32 initializationExceptionGCHandle;
#endif
    guint32 cctor_started;
    guint32 cctor_finished;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2019.1.0")}
    __attribute__((aligned(8))) size_t cctor_thread;
#else
    __attribute__((aligned(8))) guint64 cctor_thread;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2020.2.0")}
    const struct Il2CppMetadataGenericContainerHandle * genericContainerHandle;
#else
    gint32 genericContainerIndex;
#endif
#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
    gint32 customAttributeIndex;
#endif
    guint32 instance_size;
    guint32 actualSize;
    guint32 element_size;
    gint32 native_size;
    guint32 static_fields_size;
    guint32 thread_static_fields_size;
    gint32 thread_static_fields_offset;
    guint32 flags;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.2")}
    guint32 token;
#endif
    guint16 method_count;
    guint16 property_count;
    guint16 field_count;
    guint16 event_count;
    guint16 nested_type_count;
    guint16 vtable_count;
    guint16 interfaces_count;
    guint16 interface_offsets_count;
    guint8 typeHierarchyDepth;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.4.4") && +!UnityVersion.CURRENT.isEqual("5.5.0")}
    guint8 genericRecursionDepth;
#endif
    guint8 rank;
    guint8 minimumAlignment;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.3.8")}
    guint8 naturalAligment;
#endif
    guint8 packingSize;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.3.0")}
    guint8 initialized_and_no_error: 1;
#endif
    guint8 valuetype: 1;
    guint8 initialized: 1;
    guint8 enumtype: 1;
    guint8 is_generic: 1;
    guint8 has_references: 1;
    guint8 init_pending: 1;
    guint8 size_inited: 1;
    guint8 has_finalize: 1;
    guint8 has_cctor: 1;
    guint8 is_blittable: 1;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.3")}
    guint8 is_import_or_windows_runtime: 1;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.5.0")}
    guint8 is_vtable_initialized: 1;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.2.0")}
    guint8 has_initialization_error: 1;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.5.0")}
    VirtualInvokeData vtable[32];
#endif
};

guint16
il2cpp_class_get_interface_count (const Il2CppClass * klass)
{
    return klass->interfaces_count;
}

guint16
il2cpp_class_get_method_count (const Il2CppClass * klass)
{
    return klass->method_count;
}

guint16
il2cpp_class_get_field_count (const Il2CppClass * klass)
{
    return klass->field_count;
}

guint8
il2cpp_class_has_static_constructor (const Il2CppClass * klass)
{
    return klass->has_cctor;
}

guint32
il2cpp_class_is_static_constructor_finished (const Il2CppClass * klass)
{
    return klass->cctor_finished;
}

#if ${+UnityVersion.CURRENT.isBelow("2019.3.0")}
gpointer
il2cpp_class_get_static_field_data (const Il2CppClass * klass)
{
    return klass->static_fields;
}
#endif

struct _Il2CppGenericInst
{
    guint32 type_argc;
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
    gint32 typeDefinitionIndex;
#endif
    Il2CppGenericContext context;
    Il2CppClass * cached_class;
};

Il2CppClass *
il2cpp_generic_class_get_cached_class (Il2CppGenericClass * class)
{
    return class->cached_class;
}

guint32
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
    const gchar * name;
    const Il2CppType * type;
    Il2CppClass * parent;
    gint32 offset;
#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
    gint32 customAttributeIndex;
#endif
#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.2")}
    guint32 token;
#endif
};

guint8
il2cpp_field_is_instance (FieldInfo * field)
{
    return (field->type->attrs & FIELD_ATTRIBUTE_STATIC) == 0;
}

#if ${+UnityVersion.CURRENT.isBelow("2019.3.0")}
guint8
il2cpp_field_is_literal (FieldInfo * field)
{
    return (field->type->attrs & FIELD_ATTRIBUTE_LITERAL) == 0;
}
#endif

struct _ParameterInfo
{
    const gchar * name;
    gint32 position;
    guint32 token;
#if ${+UnityVersion.CURRENT.isBelow("2018.3.0")}
    gint32 customAttributeIndex;
#endif
    const Il2CppType * parameter_type;
};

const gchar *
il2cpp_parameter_get_name(const ParameterInfo * parameter)
{
    return parameter->name;
}

const Il2CppType *
il2cpp_parameter_get_type (const ParameterInfo * parameter)
{
    return parameter->parameter_type;
}

gint32
il2cpp_parameter_get_position (const ParameterInfo * parameter)
{
    return parameter->position;
}

struct _MethodInfo
{
    gpointer methodPointer;
    gpointer invoker_method;
    const gchar * name;
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
    gint32 customAttributeIndex;
#endif
    guint32 token;
    guint16 flags;
    guint16 iflags;
    guint16 slot;
    guint8 parameters_count;
    guint8 is_generic: 1;
    guint8 is_inflated: 1;
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    guint8 wrapper_type: 1;
    guint8 is_marshaled_from_native: 1;
#endif
};

gpointer
il2cpp_method_get_pointer(const MethodInfo * method)
{
    return method->methodPointer;
}

const ParameterInfo *
il2cpp_method_get_parameters (const MethodInfo * method,
                              void ** iter)
{   
    guint16 parameters_count = method->parameters_count;
    
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
    gint32 length;
    Il2CppChar chars[32];
};

void
il2cpp_string_set_length (Il2CppString * string,
                          gint32 length)
{
    string->length = length;
}

struct _Il2CppArray
{
    Il2CppObject obj;
    struct Il2CppArrayBounds * bounds;
    guint32 max_length;
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
    guint32 max_length;
    __attribute__((aligned(8))) gpointer vector[32];
#else
    Il2CppArray Array;
    __attribute__((aligned(8))) gpointer vector;
#endif
};
#endif

#if ${+UnityVersion.CURRENT.isEqualOrAbove("5.3.3")}
gpointer
il2cpp_array_elements (Il2CppArraySize * array) {
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    return array->vector;
#else
    return &array->vector;
#endif
}
#else
gpointer
il2cpp_array_elements (Il2CppArray * array) {
    return (void*) array->vector;
}
#endif

const gchar *
il2cpp_class_get_type_name (const Il2CppClass * klass)
{
#if ${+UnityVersion.CURRENT.isEqualOrAbove("2018.1.0")}
    return il2cpp_type_get_name (&klass->byval_arg);
#else
    return il2cpp_type_get_name (klass->byval_arg);
#endif
}

const gchar *
il2cpp_class_to_string (const Il2CppClass * klass)
{
    GString * text;

    text = g_string_new (NULL);

    g_string_append_printf (text, "// %s\\n", klass->image->name);
    
    guint8 is_enum = klass->enumtype;
    guint8 is_valuetype = klass->valuetype;
    guint8 is_interface = klass->flags & TYPE_ATTRIBUTE_INTERFACE;
    
    if (is_enum) g_string_append_len (text, "enum ", 5);
    else if (is_valuetype) g_string_append_len (text, "struct ", 7);
    else if (is_interface) g_string_append_len (text, "interface ", 10);
    else g_string_append_len (text, "class ", 6);

    g_string_append (text, il2cpp_class_get_type_name (klass));

    Il2CppClass * parent = klass->parent;
    guint16 interfaces_count = klass->interfaces_count;
    if (parent != NULL || interfaces_count > 0) g_string_append_len (text, " : ", 3);
    
    if (parent != NULL) g_string_append (text, il2cpp_class_get_type_name (parent));
    
    for (guint16 i = 0; i < interfaces_count; i++)
    {   
        if (i > 0 || parent != NULL) g_string_append_len (text, ", ", 2);
        g_string_append (text, il2cpp_class_get_type_name (klass->implementedInterfaces[i]));
    }
    
    g_string_append_len (text, "\\n{", 2);

    guint16 field_count = klass->field_count;
    if (field_count > 0)
    {
        FieldInfo * field;
        for (guint16 i = 0; i < field_count; i++)
        {
            field = klass->fields + i;
            g_string_append_len (text, "\\n    ", 5);

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

    guint16 method_count = klass->method_count;
    if (method_count > 0)
    {
        const MethodInfo * method;

        if (field_count > 0) g_string_append_c (text, '\\n');
        for (guint16 i = 0; i < method_count; i++)
        {
            method = klass->methods[i];
            g_string_append_len (text, "\\n    ", 5);
            
            guint8 is_static_flag = method->flags & METHOD_ATTRIBUTE_STATIC;
            
            if (is_static_flag != 0) g_string_append_len (text, "static ", 7);
            g_string_append_printf (text, "%s %s(", il2cpp_type_get_name (method->return_type), method->name);

            const ParameterInfo * param;

            guint16 parameters_count = method->parameters_count;
            for (guint8 j = 0; j < parameters_count; j++)
            {
                param = method->parameters + j;
                if (j > 0) g_string_append_len (text, ", ", 2);
                g_string_append_printf (text, "%s %s", il2cpp_type_get_name (param->parameter_type), param->name);
            }

            g_string_append_len (text, ");", 2);
            gpointer method_pointer = method->methodPointer;
            if (method_pointer != NULL) g_string_append_printf (text, " // 0x%.8x", GPOINTER_TO_INT (method->methodPointer) - IL2CPP_BASE);
        }
    }

    g_string_append_len (text, "\\n}\\n\\n", 4);

    return g_string_free (text, 0);
}

struct _Il2CppMetadataSnapshot
{
    guint32 typeCount;
    struct Il2CppMetadataType * types;
};

struct _Il2CppManagedMemorySection
{
    guint64 sectionStartAddress;
    guint32 sectionSize;
    guint8 * sectionBytes;
};

struct _Il2CppManagedHeap
{
    guint32 sectionCount;
    Il2CppManagedMemorySection * sections;
};

struct _Il2CppStacks
{
    guint32 stackCount;
    Il2CppManagedMemorySection * stacks;
};

struct _Il2CppGCHandles
{
    guint32 trackedObjectCount;
    Il2CppObject ** pointersToObjects;
};

struct _Il2CppRuntimeInformation
{
    guint32 pointerSize;
    guint32 objectHeaderSize;
    guint32 arrayHeaderSize;
    guint32 arrayBoundsOffsetInHeader;
    guint32 arraySizeOffsetInHeader;
    guint32 allocationGranularity;
};

struct _Il2CppManagedMemorySnapshot
{
    Il2CppManagedHeap heap;
    Il2CppStacks stacks;
    Il2CppMetadataSnapshot metadata;
    Il2CppGCHandles gcHandles;
    Il2CppRuntimeInformation runtimeInformation;
    gpointer additionalUserInformation;
};

guint32
il2cpp_memory_snapshot_get_tracked_object_count (Il2CppManagedMemorySnapshot * snapshot)
{
    return snapshot->gcHandles.trackedObjectCount;
}

Il2CppObject **
il2cpp_memory_snapshot_get_objects (Il2CppManagedMemorySnapshot * snapshot)
{
    return snapshot->gcHandles.pointersToObjects;
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
    choose2: choose2,

    async initialize() {
        if (Process.platform != "linux" && Process.platform != "windows") {
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
