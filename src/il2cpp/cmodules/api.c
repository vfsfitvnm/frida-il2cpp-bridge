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

#ifndef IL2CPP_CSTRING_SET_LENGTH_OFFSET
#define IL2CPP_CSTRING_SET_LENGTH_OFFSET 0
#endif

#ifndef IL2CPP_CARRAY_GET_ELEMENTS_OFFSET
#define IL2CPP_CARRAY_GET_ELEMENTS_OFFSET 0
#endif

#ifndef IL2CPP_CLASS_GET_ACTUAL_INSTANCE_SIZE_OFFSET
#define IL2CPP_CLASS_GET_ACTUAL_INSTANCE_SIZE_OFFSET 0
#endif

#ifndef IL2CPP_METHOD_GET_POINTER_OFFSET
#define IL2CPP_METHOD_GET_POINTER_OFFSET 0
#endif

extern const char * il2cpp_class_get_name (void *);
extern int il2cpp_field_get_flags (void *);
extern size_t il2cpp_field_get_offset (void *);
extern uint32_t il2cpp_method_get_flags (void *, uint32_t *);
extern char * il2cpp_type_get_name (void *);
extern Il2CppTypeEnum il2cpp_type_get_type_enum (void *);
extern void il2cpp_free (void *);

void
il2cpp_string_set_length (int32_t * string, int32_t length)
{
  *(string + IL2CPP_CSTRING_SET_LENGTH_OFFSET) = length;
}

void *
il2cpp_array_get_elements (int32_t * array)
{
  return array + IL2CPP_CARRAY_GET_ELEMENTS_OFFSET;
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

  return ((type_enum >= IL2CPP_TYPE_BOOLEAN && type_enum <= IL2CPP_TYPE_R8) ||
          type_enum == IL2CPP_TYPE_I || type_enum == IL2CPP_TYPE_U);
}

int32_t
il2cpp_class_get_actual_instance_size (int32_t * class)
{
  return *(class + IL2CPP_CLASS_GET_ACTUAL_INSTANCE_SIZE_OFFSET);
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

    if (c == ']')
      rank++;
    else if (c == '[' || rank == 0)
      break;
    else if (c == ',')
      rank++;
    else
      break;
  }

  return rank;
}

const char *
il2cpp_field_get_modifier (void * field)
{
  int flags;

  flags = il2cpp_field_get_flags (field);

  switch (flags & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK)
  {
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

  switch (flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK)
  {
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
  return *(method + IL2CPP_METHOD_GET_POINTER_OFFSET);
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
il2cpp_memory_snapshot_get_classes (
    const Il2CppManagedMemorySnapshot * snapshot, Il2CppMetadataType ** iter)
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

      if (metadata_type < snapshot->metadata_snapshot.types +
                              snapshot->metadata_snapshot.type_count)
      {
        *iter = metadata_type;
        return (uintptr_t) (*iter)->type_info_address;
      }
    }
  }
  return 0;
}

struct Il2CppGCHandles
il2cpp_memory_snapshot_get_gc_handles (
    const Il2CppManagedMemorySnapshot * snapshot)
{
  return snapshot->gc_handles;
}

struct Il2CppRuntimeInformation
il2cpp_memory_snapshot_get_information (
    const Il2CppManagedMemorySnapshot * snapshot)
{
  return snapshot->runtime_information;
}
