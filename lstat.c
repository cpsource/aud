#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <dirent.h>

#include "bldaudtab.h"
#include "lstat.h"

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

void recurse_add_files ( char *cdir )
{
  struct stat sb;
  char wbuf[1024];
  DIR *dir = NULL;
  struct dirent *de;
  static int depth = 0;
  //char *c,*d;
  
  if ( is_on_cl(cdir) ) {
    goto finis;
  }

  depth += 1;

  // debug
  //printf("%s: cdir = <%s>\n",__FUNCTION__, cdir);
  
  // a directory
  dir = opendir(cdir);
  if ( !dir ) {
    fprintf(stderr,"%s: WARNING, can't open directory <%s>\n",__FUNCTION__, cdir);
    goto finis;
  }
  while ( (de = readdir(dir)) ) {

    // skip . and ..
    if ( (0 == strcmp(de->d_name,".")) || (0 == strcmp(de->d_name,"..")) ) {
      goto cont;
    }

    sprintf(wbuf,"%s/%s",cdir,de->d_name);

    //sprintf(wbuf,"%s/%s",cdir,de->d_name);
    //printf("built string <%s>\n",wbuf);
    
    if (lstat(wbuf, &sb) == -1) {
      printf("ERROR, can't stat <%s>\n",wbuf);
      perror("stat");
      exit(EXIT_FAILURE);
    }

    switch (sb.st_mode & S_IFMT) {
    case S_IFBLK:  //  printf("block device\n");            break;
    case S_IFCHR:  //  printf("character device\n");        break;
    case S_IFIFO:  //  printf("FIFO/pipe\n");               break;
    case S_IFLNK:  //  printf("symlink\n");                 break;
    case S_IFSOCK: //  printf("socket\n");                  break;
      goto cont;

    case S_IFDIR:  // printf("directory\n");               break;
      // recurse
      recurse_add_files(wbuf);
      break;
    case S_IFREG:  //  printf("regular file\n");            break;
      // recursively process ldd from a infile
      recursive_process_infile(wbuf, depth);
      break;
    default:       // printf("unknown?\n");                break;
      goto cont;;
      
    } // switch
  cont:;
  } // while readdir
  closedir(dir);
  
  // done, return
 finis:;
  depth -= 1;
  return;
}

//
// walk the PATH environmental variable, and add everything to our audit
// PATH is of the form: PATH=/usr/local/sbin:/usr/local/bin:
//                           /usr/sbin:/usr/bin:/sbin:/bin:/usr/games:
//                           /usr/local/games:/snap/bin:/snap/bin
// ie, each path is seperated by a ':'
void lstat_walk_path(void)
{
  char wbuf[156];
  char *path = getenv("PATH");
  char *c = path;
  char *d;

  while ( *c ) {
    d = wbuf;
    while ( *c && *c != ':' ) {
      *d++ = *c++;
    }
    *d = 0;
    recurse_add_files ( wbuf );
    if ( *c == ':' ) {
      c += 1;
      continue;
    }
    break;
  } // while
}

// walk a colon seperated path
void lstat_walk_colon_path(char *cpath)
{
  char wbuf[156];
  char *path = cpath;
  char *c = path;
  char *d;

  while ( *c ) {
    d = wbuf;
    while ( *c && *c != ':' ) {
      *d++ = *c++;
    }
    *d = 0;
    recurse_add_files ( wbuf );
    if ( *c == ':' ) {
      c += 1;
      continue;
    }
    break;
  } // while
}

#if defined(CP_MAIN)

int
main(int argc, char *argv[])
{
  struct stat sb;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pathname>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  if (lstat(argv[1], &sb) == -1) {
    perror("lstat");
    exit(EXIT_FAILURE);
  }

  printf("ID of containing device:  [%jx,%jx]\n",
	 (uintmax_t) major(sb.st_dev),
	 (uintmax_t) minor(sb.st_dev));

  printf("File type:                ");

  switch (sb.st_mode & S_IFMT) {
  case S_IFBLK:  printf("block device\n");            break;
  case S_IFCHR:  printf("character device\n");        break;
  case S_IFDIR:  printf("directory\n");               break;
  case S_IFIFO:  printf("FIFO/pipe\n");               break;
  case S_IFLNK:  printf("symlink\n");                 break;
  case S_IFREG:  printf("regular file\n");            break;
  case S_IFSOCK: printf("socket\n");                  break;
  default:       printf("unknown?\n");                break;
  }

  printf("I-node number:            %ju\n", (uintmax_t) sb.st_ino);

  printf("Mode:                     %jo (octal)\n",
	 (uintmax_t) sb.st_mode);

  printf("Link count:               %ju\n", (uintmax_t) sb.st_nlink);
  printf("Ownership:                UID=%ju   GID=%ju\n",
	 (uintmax_t) sb.st_uid, (uintmax_t) sb.st_gid);

  printf("Preferred I/O block size: %jd bytes\n",
	 (intmax_t) sb.st_blksize);
  printf("File size:                %jd bytes\n",
	 (intmax_t) sb.st_size);
  printf("Blocks allocated:         %jd\n",
	 (intmax_t) sb.st_blocks);

  printf("Last status change:       %s", ctime(&sb.st_ctime));
  printf("Last file access:         %s", ctime(&sb.st_atime));
  printf("Last file modification:   %s", ctime(&sb.st_mtime));

  exit(EXIT_SUCCESS);
}

#endif // CP_MAIN
