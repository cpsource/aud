
#include <stdio.h>
#include <stdlib.h>

void *dlopen(const char *filename, int flags)
{
  fprintf(stderr,"%s: should never get here, filename = <%s>, flags = 0x%x\n",
	  __FUNCTION__,(char *)filename, flags);
  return NULL;
}

int dlclose(void *handle)
{
  fprintf(stderr,"%s: should never get here, handle = 0x%08lx\n",
	  __FUNCTION__,(long unsigned int)handle);
  exit(0);
}
