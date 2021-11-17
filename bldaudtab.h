#ifndef __BLDAUDTAB_H__
#define __BLDAUDTAB_H__

// test if we've seen this file before
int is_on_cl(char *name);
// recursively process ldd from a infile
void recursive_process_infile(char *infile, int line);

// don't audit this file - can be a series of colon seperated files
#define NO_AUDIT "/usr/local/bin/aud"

#endif // __BLDAUDTAB_H__
