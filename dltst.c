#include <stdio.h>
#include <dlfcn.h>

void *dlopen(const char *filename, int flags);
int dlclose(void *handle);

#define _GNU_SOURCE
#include <dlfcn.h>

//       Link with -ldl.

int main(int argc, char *argv[] )
{
  void *m = dlopen("dljunk.so", 0);

  if ( m ) {
	dlclose(m);
  }

  return 0;
}
