#ifndef __SHA_H__
#define __SHA_H__

#if defined(__cplusplus)
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif // __cplusplus

/* __P is a macro used to wrap function prototypes, so that compilers
   that don't understand ANSI C prototypes still work, and ANSI C
   compilers can issue warnings about type mismatches. */
#undef __P
#if defined (__STDC__) || defined (_AIX) \
        || (defined (__mips) && defined (_SYSTYPE_SVR4)) \
        || defined(WIN32) || defined(__cplusplus)
# define __P(protos) protos
#else
# define __P(protos) ()
#endif

__BEGIN_DECLS

void sha256_hash_string (unsigned char *hash, char outputBuffer[65]);
void sha256_string(char *string, char outputBuffer[65]);
int sha256_file(char *path, char outputBuffer[65]);
int sha256_block(int blockCount, char *block, char outputBuffer[65]);
// get sha256 of a struct stat
int sha256_struct_stat(char *path, char outputBuffer[65]);

__END_DECLS

#endif // __SHA_H__
