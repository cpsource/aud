#ifndef __PIPE_H__
#define __PIPE_H__

// do the deed, warning, caller must free ptr
char *do_pipe(int argc, char *argv[] );
// cleanup
void pipe_free_output(void);

#endif // __PIPE_H__
