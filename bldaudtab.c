// read aud.txt and build our audtab.h file

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#include <dirent.h>

// used by regex
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))
static const char *const re = "(not found)|(statically linked)|(not a dynamic executable)|(linux-vdso.so.1)|(/[A-Za-z0-9./_+-]+)";

#include "openssl/sha.h"

#include "sha.h"
#include "pipe.h"
#include "lstat.h"

#include "bldaudtab.h"

// trace flag
int t_flag = 0;
// etc flag
int e_flag = 0;
// path flag
int p_flag = 0;
// -r path
int r_flag = 0;
char r_buff[1024]; // store a colon seperated series of paths

#define AUD_WAIT_TIME 10*1000

typedef struct completed_list {
  struct completed_list *n;
  char *name;
} CL;

CL *cl_root = NULL;

void show_cl(void) {

  CL *n = cl_root;
  
  while ( n ) {
#ifdef CP_TRACE
    printf("CL: %s\n",n->name);
#endif    
    // onward
    n = n->n;
  }
}
  
int is_on_cl(char *name)
{
  CL *n = cl_root;
  CL *tmp;

  show_cl();
#ifdef CP_TRACE
  printf("show_cl: searching for <%s>\n",name);
#endif  
  
  while ( n ) {
    if ( 0 == strcmp(name,n->name) ) {
      // on list already
      return 1;
    }

    // onward
    n = n->n;
  }

  // add to front of list
  tmp = malloc(sizeof(CL)); assert(tmp!=0);
  tmp->name = strdup(name);
  tmp->n = cl_root;
  cl_root = tmp;
    
  // say we just added it
  return 0;
}

//
// some handy parsing subs
//
// skip space tab
char *skip_space_tab ( char *c )
{
  char *d = c;

  while ( *d != 0 && (*d == ' ' || *d == '\t' )) {
    d += 1;
  }

  return d;
}

// tokenize a string, setup to continue
char *tokenize ( char *c, char **restartPt )
{
  char *d = c;
  
  while ( *d != 0 && *d != '\n' && !(*d == ' ' || *d == '\t' ) ) {
    d += 1;
  }

  if ( restartPt ) {
    if ( *d != 0 ) {
      *restartPt = d+1;
    } else {
      *restartPt = d;
    }
  }
  
  *d = 0;

  return c;
}

// get to next line
char *to_next_line ( char *c )
{
  char *d = c;

  while ( *d != 0 && *d != '\n' ) {
    d += 1;
  }
  if ( *d == '\n' ) d += 1;
  return d;
}

// handle calculating sha and output
void handle_output ( int fct, char *key, char *path, char *file, char *stat )
{
  static SHA256_CTX sha256;
  static FILE *outf;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  char outputBuffer[65];
  char *tmpargv[3] = { "/usr/local/bin/aud", "-a", NULL };
  char *tmp1,*tmp2;
  char *c, *d;
  char wbuf_key[1024], wbuf_path[1024];
  
  switch ( fct ) {
  case 0:
    SHA256_Init(&sha256);
    unlink("audtab.h");
    outf = fopen("audtab.h", "w");

    fprintf(outf,"struct audit_table_struct {\n");
    fprintf(outf,"  char *key;\n");
    fprintf(outf,"  char *path;\n");
    fprintf(outf,"  char *file;\n");
    fprintf(outf,"  char *stat;\n");
    fprintf(outf,"  };\n");
    fprintf(outf," struct audit_table_struct audit_table[] = {\n");

    break;

  case 1:
    // build key - duplicate backstrokes
    c = key;
    d = wbuf_key;
    while ( *c != 0 ) {
      if ( *c == '\\' ) {
	*d++ = '\\';
      }
      *d++ = *c++;
    } // while
    *d = 0;

    // build path - duplicate backstrokes    
    c = path;
    d = wbuf_path;
    while ( *c != 0 ) {
      if ( *c == '\\' ) {
	*d++ = '\\';
      }
      *d++ = *c++;
    } // while
    *d = 0;

    fprintf(outf,"  { \"%s\", \"%s\", \"%s\", \"%s\" },\n",
	    wbuf_key, wbuf_path, file, stat);
	
    SHA256_Update(&sha256, key     , strlen(key     ));
    SHA256_Update(&sha256, path    , strlen(path    ));
    SHA256_Update(&sha256, file    , strlen(file    ));
    SHA256_Update(&sha256, stat    , strlen(stat    ));

    break;

  case 2:
    // finish off table
    fprintf(outf,"  { NULL, NULL, NULL, NULL }\n");
    fprintf(outf," };\n");
    
    // output kernel verson
    fprintf(outf,"\n");
    fprintf(outf,"char *kernel_version=\"%s\";\n",key);
    SHA256_Update(&sha256, key, strlen(key));
    break;
    
  case 3:
    // output hash of aud .text
    fprintf(outf,"\n");
    usleep(AUD_WAIT_TIME);
    // we call ./aud -a to get the job done
    tmp1 = do_pipe(2,tmpargv);
    // get rid of \n
    tmp2=strchr(tmp1,'\n'); if ( NULL != tmp2 ) *tmp2 = 0;
    fprintf(outf,"char aud_text_hash[] = \"%s\";\n", tmp1);

    // add to our hash
    SHA256_Update(&sha256, tmp1, strlen(tmp1));

    // cleanup memory
    pipe_free_output();
    break;

  case 4:
    // output hash of audit_table
    SHA256_Final(hash, &sha256);
    for( int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
    fprintf(outf,"\n");
    fprintf(outf,"char *audit_table_hash = \"%s\";\n",outputBuffer);
    
    fclose(outf);
    break;
    
  } // switch
}

// recursively process ldd from a infile
void recursive_process_infile(char *infile, int line)
{
  // ask ldd to give us the info
  char *dat = NULL;
  char *args[2] = { "/usr/bin/ldd", infile };
  char *c;
  char stat_sha[65];
  char file_sha[65];
  static int depth = 0;
  char *f;

  const char *s = (const char *)infile;
  regex_t     regex;
  regmatch_t  pmatch[1];
  //regoff_t    off;
  regoff_t    len;

  char substr[132];
  char key[132];

#if defined(NO_AUDIT)
  if ( strstr(NO_AUDIT,infile) ) {
    return;
  }
#endif // NO_AUDIT
  
  depth += 1;
  
#ifdef CP_TRACE
  printf("cp1.%d: infile = <%s>\n",depth,infile);
#endif  
  
  // already done ???
  if ( is_on_cl(infile) ) {
#ifdef CP_TRACE
    printf("cp0.%d: file <%s> on cl already, returning\n",depth,infile);
#endif    
    // yes, just exit
    depth -= 1;
    return;
  }

  if ( t_flag ) {
    printf("%s.%4d.%3d: <%s>\n", __FUNCTION__, line, depth,infile);
  }
  
#ifdef CP_TRACE
  printf("cp2.%d: infile = <%s>\n",depth,infile);
#endif  
  
  c = strrchr(infile,'/');
  if ( c ) {
#ifdef CP_TRACE
    printf("cp3.%d <%s>\n",depth,infile);
#endif    
    
    c += 1;
    strcpy(key,c);
	
    if ( sha256_file        (infile, file_sha)) {
      // we got an error
      //printf("sha256_file failed on <%s>\n",infile);
      //exit(0);
      depth -= 1;
      return;
    }
    
    sha256_struct_stat (infile, stat_sha);

    handle_output ( 1, key, infile, file_sha, stat_sha);
  }

  //
  // now, lets dig into what libraries are linked
  // with this image. Use ldd.
  //
  
#ifdef CP_TRACE
  printf("cp4.%d: <%s> <%s>\n",depth,infile,args[1]);
#endif  
  
  // dance around a bit as we must be recursive
  usleep(AUD_WAIT_TIME);
  f = do_pipe(2,args);
#if defined(CP_TRACE)
  printf("cp4x.%d do_pipe returns <%s>\n",depth,f);
#endif  
  if ( !f ) {
    // done
    depth -= 1;
    return;
  }
  if ( 0 == strcmp("ldd: exited with unknown exit code (139)\n",f) ) {
    depth -= 1;
    // don't memory leak
    pipe_free_output();
    return;
  }

  // make copy of string rturned
  dat = strdup(f);
  // don't memory leak
  pipe_free_output();

#ifdef CP_TRACE
  printf("cp5.%d: (from do_pipe) dat = <%s>\n",depth,dat);
#endif  

  // Note dat will look something like this
  //
  //   linux-vdso.so.1 (0x00007ffd109a1000)
  //   libcrypto.so.1.1 => /lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007fcac5f23000)
  //   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcac5d37000)
  //   libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fcac5d30000)
  //   libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fcac5d0e000)
  //   libFUBAR.so.O => not found
  //   /lib64/ld-linux-x86-64.so.2 (0x00007fcac6216000)
  //

  if (regcomp(&regex, re, REG_NEWLINE|REG_EXTENDED))
    exit(EXIT_FAILURE);

  s = dat;
  
  //printf("String = \"%s\"\n", s);
  //printf("Matches:\n");

  // walk the list
  for (int j = 0; ; j++) {
    
    if (regexec(&regex, s, ARRAY_SIZE(pmatch), pmatch, 0))
      break;
    
    //off = pmatch[0].rm_so + (s - dat);
    len = pmatch[0].rm_eo - pmatch[0].rm_so;
    //printf("#%d:\n", j);
    //printf("offset = %jd; length = %jd\n", (intmax_t) off,
    // (intmax_t) len);
    //sprintf(substr,"substring = \"%.*s\"\n", len, s + pmatch[0].rm_so);
    sprintf(substr,"%.*s", len, s + pmatch[0].rm_so);
    //printf("substr = <%s>\n",substr);

    // now do parsing

    if ( 0 == strcmp(substr,"not a dynamic executable") ) {
      // no further work required
      //printf("cp6.%d: not a dynamic executable, returning\n", depth);
      goto onward;
    }
    //                       statically linked
    if ( 0 == strcmp(substr,"statically linked") ) {
      // no further work required
      //printf("cp6.%d: statically linked, returning\n", depth);
      goto onward;
    }
    // not found
    if ( 0 == strcmp(substr,"not found") ) {
      // no further work required
      //printf("not found\n");
      goto onward;
    }
    //
    //    linux-vdso.so.1
    //
    if ( 0 == strcmp(substr,"linux-vdso.so.1") ) {
      // skip for now
      //printf("skipping linux-vdso.so.1\n");
      goto onward;
    }

    //
    // the only thing left is /some/file...
    //

    // lets recurse
    recursive_process_infile(substr, line);
    
    // onward
  onward:
    s += pmatch[0].rm_eo;
  }

  // done parsing the list
  
  // cleanup
  if ( dat ) free(dat);
  depth -= 1;
    
  // done
}

char kernel_version[132] = {0};
void get_kernel_version(void)
{
  char *args[2] = { "/usr/bin/uname", "-a" };
  char *res;
  char *c,*d;

  usleep(AUD_WAIT_TIME);  
  res = do_pipe(2,args);

  // now parse it
  c = res;
  if ( c ) {
    c = strchr(c,' ');
    if ( c ) {
      c += 1;
      c = strchr(c,' ');
      if ( c ) {
	c += 1;
	// now c points to the start of the kernel_version
	d = kernel_version;
	while ( *c != ' ' ) {
	  *d++ = *c++;
	}
	*d = 0;
      }
    }
  }
  
  // don't memory lea
  pipe_free_output();
}

//
//#include <sys/types.h>
//#include <dirent.h>
//
// DIR *opendir(const char *name);
// struct dirent *readdir(DIR *dirp);
//           struct dirent {
//               ino_t          d_ino;       /* Inode number */
//               off_t          d_off;       /* Not an offset; see below */
//               unsigned short d_reclen;    /* Length of this record */
//               unsigned char  d_type;      /* Type of file; not supported
//                                              by all filesystem types */
//               char           d_name[256]; /* Null-terminated filename */
//           };
//#include <sys/types.h>
//#include <dirent.h>
// int closedir(DIR *dirp);
//

// get files from /lib/modules/<kernel_version>/vdso/. and check them
void audit_lib_modules_vdso(int line)
{
  DIR *dir;
  char wbuf[256];
  struct dirent *de;
  char *c;
  
  sprintf(wbuf,"/lib/modules/%s/vdso/.", kernel_version);
  dir = opendir(wbuf);

  if ( dir ) {
    c = strrchr(wbuf,'.');
    if ( c ) {
      while ( (de = readdir(dir)) ) {
	// don't audit . and ..
	//if ( 0 == strcmp(".",de->d_name) ) continue;
	//if ( 0 == strcmp("..",de->d_name) ) continue;
	if ( de->d_name[0] == 'v' && de->d_name[1] == 'd' ) {
	  // build our full file path
	  strcpy(c,de->d_name);
	  // go check it
	  recursive_process_infile(wbuf,line);
	} // if de
      } // while
    } // if c
    closedir(dir);
  } // if dir

  return;
}

int main(int argc, char *argv[] )
{
  char wbuf[256];
  FILE *inf = fopen("aud.txt","r");
  char *c;
  int line = 0;
  int arg = 1;

  // process all flags
  while ( arg < argc ) {

    if ( argv[arg][0] == '-' && argv[arg][1] == 't' ) {
      t_flag = 1;
    }
    if ( argv[arg][0] == '-' && argv[arg][1] == 'e' ) {
      e_flag = 1;
    }
    if ( argv[arg][0] == '-' && argv[arg][1] == 'p' ) {
      p_flag = 1;
    }
    if ( argv[arg][0] == '-' && argv[arg][1] == 'r' ) {
      if ( r_flag + strlen(&argv[arg][2]) + 3 /* why 3? defensive programming! */ >= sizeof(r_buff) ) {
	printf("too many -r - add to aud.txt instead\n");
      } else {
	sprintf(&r_buff[r_flag],"%s:",&argv[arg][2]);
	r_flag = strlen(r_buff);
      }
    }
    // on to next argument
    arg += 1;
  } // while arg
  
  if ( !inf ) {
    printf("bldaudtab: no aud.txt input file\n");
    exit(0);
  }

  get_kernel_version();
  if ( t_flag ) {
    printf("kernel version = <%s>\n",kernel_version);
  }

  // init
  handle_output ( 0, NULL, NULL, NULL, NULL );

  // add -r if any
  if ( r_flag ) {
    if ( r_buff[r_flag-1] == ':' ) {
      r_buff[r_flag-1] = 0;
    }
    lstat_walk_colon_path(r_buff);
  }
  
  // add PATH
  if ( p_flag ) {
    lstat_walk_path();
  }
  // add /etc
  if ( e_flag ) {
    recurse_add_files ( "/etc" );
  }
  
  while ( fgets(wbuf,256,inf) ) {
    // sanity check line
    line += 1;
    c = strchr(wbuf,'\n'); if ( c ) *c = 0;
    c = wbuf;
    if ( *c == 0 ) continue;
    if ( *c == '%' ) continue;
    if ( *c == '#' ) continue;

    // recurse
    recursive_process_infile(wbuf,line);

  } // while
  
  // process any vdso
  audit_lib_modules_vdso(line);
  
  // output kernel version
  handle_output ( 2, kernel_version, NULL, NULL, NULL );

  // output text sha
  handle_output ( 3, NULL, NULL, NULL, NULL );

  // output audit_table_hash
  handle_output ( 4, NULL, NULL, NULL, NULL );
  
  fclose(inf);
  return 0;
}
