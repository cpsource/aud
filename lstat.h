#ifndef __LSTAT_H__
#define __LSTAT_H__

// walk a directory and add all files
void recurse_add_files ( char *dir );
// walk PATH and add files to audit
void lstat_walk_path(void);
// walk a colon seperated path
void lstat_walk_colon_path(char *cpath);

#endif // __LSTAT_H__
