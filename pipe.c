// perform an ldd in file and print results

// see also http://www.microhowto.info/howto/capture_the_output_of_a_child_process_in_c.html
// see also http://www.microhowto.info/howto/reap_zombie_processes_using_a_sigchld_handler.html

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

#include "pipe.h"

static int output_cnt = 0;
static char *output = NULL;

// cleanup memory
void pipe_free_output(void) {
  if ( output ) {
    free(output);
    output = NULL;
    output_cnt = 0;
  }
  return;
}

// append to output one way or the other
static char *handle_child_process_output(char *buffer, int count) {

  //printf("%s: entry\n",__FUNCTION__);
  
  if ( NULL == output ) {
    output = malloc(count+1);
    output_cnt = count+1;
    memcpy(output,buffer,count);
    output[count] = 0;
  } else {
    output = realloc(output,output_cnt+count);
    memcpy(output + output_cnt-1,buffer,count);
    output_cnt += count;
    output[output_cnt-1] = 0;
  }
      
  return output;
}

// do the deed, warning, caller must free ptr
char *do_pipe(int argc, char *argv[] )
{
  int pipefd[2]; // 0 is read, 1 is write fd
  pid_t cpid;
  char *res = NULL;

  // onward
  if (pipe(pipefd) == -1) {
    perror("pipe");
    exit(EXIT_FAILURE);
  }

  // do this in case the child exec's
  if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) == -1) {
    perror("fcntl");
    exit(1);
  }

  // make two of us
  cpid = fork();
  if (cpid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  }

  if (cpid == 0) {    /* Child reads from pipe */

    // child code

    while ((dup2(pipefd[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
    while ((dup2(pipefd[1], STDERR_FILENO) == -1) && (errno == EINTR)) {}
    close(pipefd[0]);
    close(pipefd[1]);
	  
    // off we go
    switch ( argc ) {
    case 1:
      execl(argv[0], argv[0], NULL);
      break;
    case 2:
      execl(argv[0], argv[0], argv[1], NULL);
      break;
    case 3:
      execl(argv[0], argv[0], argv[1], argv[2], NULL);
      break;
    case 4:
      execl(argv[0], argv[0], argv[1], argv[2], argv[3], NULL);
      break;
    default:
      fprintf(stderr,"do_pipe: argc = %d not supported\n",argc);
      exit(0);
      break;
    }

    // should never get here
    perror("execl");
    _exit(1);
  
  } else {            /* Parent writes argv[1] to pipe */

    // parent code

    close(pipefd[1]);

    char buffer[4096];
    while (1) {
      ssize_t count = read(pipefd[0], buffer, sizeof(buffer));
      if (count == -1) {
	if (errno == EINTR) {
	  continue;
	} else {
	  perror("read");
	  exit(1);
	}
      } else if (count == 0) {
	break;
      } else {
#if 0
	// for debugging, print buffer
	int i;
	for ( int i = 0 ; i < count ; i++ ) {
	  printf("%c",buffer[i]);
	}
#endif	
	res = handle_child_process_output(buffer, count);
      }
    }
 
    close(pipefd[0]);
    wait(NULL);                /* Wait for child */
    return res;
  } // parent process
}

