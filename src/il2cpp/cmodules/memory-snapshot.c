#include <stdint.h>
#include <string.h>

typedef struct Il2CppManagedMemorySnapshot Il2CppManagedMemorySnapshot;
typedef struct Il2CppMetadataType Il2CppMetadataType;

struct Il2CppManagedMemorySnapshot
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
    void ** pointers_to_objects;
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

struct Il2CppMetadataType
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

uintptr_t
il2cpp_memory_snapshot_get_classes (
    const Il2CppManagedMemorySnapshot * snapshot, Il2CppMetadataType ** iter)
{
  const int zero = 0;
  const void * null = 0;

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

void **
il2cpp_memory_snapshot_get_objects (
    const Il2CppManagedMemorySnapshot * snapshot, uint32_t * size)
{
  *size = snapshot->gc_handles.tracked_object_count;
  return snapshot->gc_handles.pointers_to_objects;
}
