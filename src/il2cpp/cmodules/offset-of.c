#include <stdint.h>

#define OFFSET_OF(name, type)                                                  \
  int16_t name (char * p, type e)                                              \
  {                                                                            \
    for (int16_t i = 0; i < 512; i++)                                          \
      if (*((type *) p + i) == e)                                              \
        return i;                                                              \
    return -1;                                                                 \
  }

OFFSET_OF (offset_of_int32, int32_t)
OFFSET_OF (offset_of_pointer, void *)
