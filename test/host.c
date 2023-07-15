#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int
main (int argc, char ** argv)
{
  char * path = argv[1];
  char * so = "GameAssembly.so";
  char * data = "Data";

  char * sopath = malloc (strlen (path) + 1 + strlen (so) + 1);
  sprintf (sopath, "%s/%s", path, so);

  char * datapath = malloc (strlen (path) + 1 + strlen (data) + 1);
  sprintf (datapath, "%s/%s", path, data);

  void * handle = dlopen (sopath, RTLD_LAZY);

  if (handle == NULL)
  {
    printf ("Couldn't find shared library at %s\n", sopath);
    return -1;
  }

  free (sopath);

  void (*il2cpp_set_data_dir) (const char *) =
      dlsym (handle, "il2cpp_set_data_dir");

  (*il2cpp_set_data_dir) (datapath);

  free (datapath);

  int (*il2cpp_init) (const char *) = dlsym (handle, "il2cpp_init");

  (*il2cpp_init) ("IL2CPP ROOT DOMAIN");

  int status;
  wait (&status);
}