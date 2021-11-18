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
#include <syslog.h>

#include "openssl/sha.h"

#include "sha.h"
#include "pipe.h"

#include "audtab.h"

// gcc magic - points to start end end of .text section at run-time
extern unsigned char __executable_start;
extern unsigned char __etext;

// .text changes here for no reason, do not audit
#define STRANGE_1 0x370
#define STRANGE_2 32

// for debugging, if -z on command line, dump .text for debug
int zmain(void)
{
  // audit our own .text, exit if asked to
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  char outputBuffer[65];
  unsigned char *string = &__executable_start;
  unsigned int len = &__etext - &__executable_start;
  unsigned char *c;
  int j = 0;
  unsigned int off = 0;

  SHA256_Init(&sha256);

  // skip strange section
  SHA256_Update(&sha256, string, STRANGE_1);
  string += (STRANGE_1 + STRANGE_2);
  len -= (STRANGE_1 + STRANGE_2);
  SHA256_Update(&sha256, string, len);

  SHA256_Final(hash, &sha256);

  sha256_hash_string (hash,outputBuffer);
  printf("%s\n",outputBuffer);
  
  printf("len = %x\n",len);
  printf(".text start: %08lx .text end: %08lx\n",(unsigned long int)&__executable_start,(unsigned long int)&__etext);
  
  printf("%08x: ",off);
  // now display .text
  c = &__executable_start;
  while ( len ) {
    printf("%02x ",*c);
    c += 1;
    len -= 1;
    off += 1;
    
    j += 1;
    if ( j > 15 ) {
      j = 0;
      printf("\n");
      printf("%08x: ",off);
    }
  }
  printf("\n");
  
  return 0;
}

char actual_kernel_version[132];

int verify_kernel_version(void)
{
  int sts = 0; // no error
  char *argv[3] = { "/usr/bin/uname" , "-a", NULL };
  char *tmp1, *c, *dst = actual_kernel_version;;
  
  tmp1 = do_pipe(2,argv);

  // get rid of \n
  c=strchr(tmp1,'\n'); if ( c ) *c = 0;
  // tmp1 now resembles: Linux Ubuntu-21 5.11.0-40-generic #44-Ubuntu SMP Wed Oct 20 16:16:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

  // get kv from string - it is just after the second space
  c = strchr(tmp1,' ');
  if ( c ) {
    c += 1;
    c = strchr(c,' ');
    if ( c ) {
      c += 1;
      while ( *c != ' ' ) {
	*dst++ = *c++;
      }
      *dst = 0;

      // match ???
      if ( strcmp(actual_kernel_version,kernel_version)) {
	// no
	sts += 1;
      }
    }
  }
  
  // cleanup memory
  pipe_free_output();

  return sts;
}

// audit audit_table
int audit_audit_table(void)
{
  struct audit_table_struct *n = audit_table;
  SHA256_CTX sha256;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  char outputBuffer[65];

  SHA256_Init(&sha256);
  
  while ( n->key ) {

    SHA256_Update(&sha256, n->key, strlen(n->key));
    SHA256_Update(&sha256, n->path, strlen(n->path));
    SHA256_Update(&sha256, n->file, strlen(n->file));
    SHA256_Update(&sha256, n->stat, strlen(n->stat));

    // onward
    n += 1;
  }

  SHA256_Update(&sha256, kernel_version, strlen(kernel_version));

  SHA256_Update(&sha256, aud_text_hash, strlen(aud_text_hash));

  // output hash of audit_table
  SHA256_Final(hash, &sha256);
  for( int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
      sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
  outputBuffer[64] = 0;

  // did it match ???
  if ( 0 == strcmp(outputBuffer,audit_table_hash) ) {
    // yes
    return 1;
  }
  // no
  return 0;
}

// spin through audit_table, checking as we go
/// Returns count of errors
int spin_audit_table(void)
{
  struct audit_table_struct *ats = audit_table;
  int sts = 0;
  char outputBuffer[65];

  while ( ats-> path ) {
    int fflag, sflag;
    
    sha256_file(ats->path, outputBuffer);
    fflag = 0;
    if ( 0 == strcmp(outputBuffer,ats->file) ) {
      fflag = 1;
    }
    
    sflag = 0;
    sha256_struct_stat(ats->path, outputBuffer);
    if ( 0 == strcmp(outputBuffer,ats->stat) ) {
      sflag = 1;
    }

    // any error ???
    if ( !sflag || !sflag ) {
      // yes
      if ( fflag ) {
	//printf("Audit: OK - file: %s\n", ats->key );
      } else {
	sts += 1;
	printf("Audit: FAIL - file: %s\n", ats->key );
      }
      if ( sflag ) {
	//printf("Audit: OK - stat: %s\n", ats->key );
      } else {
	sts += 1;
	printf("Audit: FAIL - stat: %s\n", ats->key );
      }
    }
    
    // onward
    ats += 1;
  }

  return sts;
}

int main ( int argc, char *argv[] )
{
  int sts = 0;
  unsigned char *c;
  int fail_count = 0;

  // audit our own .text, exit if asked to
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  char outputBuffer[65];
  char version_string[128];
  unsigned char *string = &__executable_start;
  unsigned int len = &__etext - &__executable_start;

  sprintf(version_string,"aud: Version:%s", AUD_VERSION);
  // setup syslog
  openlog((const char *)version_string, /* const char *ident */
	  0                             /* int option        */,
	  LOG_AUTH                      /* int facility      */);
  
  // init sha256
  SHA256_Init(&sha256);

  // skip strange section
  SHA256_Update(&sha256, string, STRANGE_1);
  string += (STRANGE_1 + STRANGE_2);
  len -= (STRANGE_1 + STRANGE_2);
  SHA256_Update(&sha256, string, len);
  
  SHA256_Final(hash, &sha256);
  sha256_hash_string (hash,outputBuffer);
  
  if ( argc > 1 && argv[1][0] == '-' && argv[1][1] == 'a' ) {
    printf("%s\n",outputBuffer);
    exit(0);
  }
  if ( argc > 1 && argv[1][0] == '-' && argv[1][1] == 'z' ) {
    zmain();
    exit(0);
  }
  // used with export LD_DEBUG="all" to trace ld linkages
  if ( argc > 1 && argv[1][0] == '-' && argv[1][1] == 'x' ) {
    exit(0);
  }

  printf("%s: Version: %s\n",
	 argv[0],
	 AUD_VERSION);

  //printf("%s\n",outputBuffer);
  //printf("%s\n",aud_text_hash);

  if ( verify_kernel_version() ) {
    fprintf(stderr,"Audit: FAIL - kernel version mismatch\n");
    fail_count += 1;
  }
  
  if ( 0 == strcmp(outputBuffer,aud_text_hash) ) {
    //fprintf(stderr,"Audit: OK - aud .text\n");
  } else {
    fprintf(stderr,"Audit: FAIL - aud .text\n");
 
    fprintf(stderr,"Calc: %s\n", outputBuffer);
    fprintf(stderr,"Stor: %s\n", aud_text_hash);
    
    fail_count += 1;
  }
  
  if ( 0 != strcmp(argv[0],"/usr/local/bin/aud") ) {
    fprintf(stderr,"Audit: FAIL - aud not run from proper disk location %s\n",argv[0]);
    fail_count += 1;
  } else {
    //fprintf(stderr,"Audit: OK - aud run from proper disk location\n");
  }
  
  if ( audit_audit_table() ) {
    //printf("Audit: OK - audit_table\n");
  } else {
    printf("Audit: FAIL -  audit_table\n");
    fail_count += 1;
  }

  if ( (c = (unsigned char *)getenv("LD_PRELOAD")) != NULL) {
    printf("Audit: FAIL -  LD_PRELOAD defined as <%s>\n",c);
    fail_count += 1;
  } else {
    //printf("Audit: OK - LD_PRELOAD not defined\n");
  }

  // walk audit table
  fail_count += spin_audit_table();

  // stats
  printf("Audit Fails: %d\n", fail_count);

  // void vsyslog(int priority, const char *format, va_list ap);
  if ( fail_count ) {
    char aud_buffer[132];
    sprintf(aud_buffer,"Audit Fails: %d",fail_count);
    syslog(LOG_ERR, "%s", aud_buffer);
    sts = (fail_count << 16) | 1;
  }
  
  // done
  closelog();
  
  return sts;
}
