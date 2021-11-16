#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "openssl/sha.h"

#include "sha.h"

// -I/opt/ssl/include/ -L/opt/ssl/lib/ -lcrypto 

void sha256_hash_string (unsigned char *hash, char outputBuffer[65])
{
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

// get sha256 of a string
void sha256_string(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

// get sha256 of a file
int sha256_file(char *path, char outputBuffer[65])
{
  FILE *file = fopen(path, "rb");

  if ( !file ) {
    fprintf(stderr, "sha256_file: can't open file <%s>\n", path);
    // post error
    return 1;
  }
  
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  const int bufSize = 32768;
  unsigned char *buffer = malloc(bufSize);
  int bytesRead = 0;
  
  if ( !buffer ) return ENOMEM;
  
  while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
      SHA256_Update(&sha256, buffer, bytesRead);
    }
  SHA256_Final(hash, &sha256);
  
  sha256_hash_string(hash, outputBuffer);
  fclose(file);
  free(buffer);
  return 0;
}

// get sha256 of a block of memory
int sha256_block(int blockCount, char *block, char outputBuffer[65])
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;

  SHA256_Init(&sha256);

  SHA256_Update(&sha256, block, blockCount);

  SHA256_Final(hash, &sha256);
  
  sha256_hash_string(hash, outputBuffer);

  return 0;
}

// get sha256 of a struct stat
int sha256_struct_stat(char *path, char outputBuffer[65])
{
  int sts;
  struct stat statbuf;
  
  sts = stat(path,&statbuf);
  if ( sts ) {
    printf("sha256_struct_stat: stat failed with errno = %d\n",sts);
    exit(0);
  }

  // don't count this
  memset(&statbuf.st_atim,0,sizeof(struct timespec));   /* Time of last access        */
  memset(&statbuf.st_mtim,0,sizeof(struct timespec));   /* Time of last modification  */
  memset(&statbuf.st_ctim,0,sizeof(struct timespec));   /* Time of last status change */
  
  sts = sha256_block(sizeof(struct stat), (char *)&statbuf, outputBuffer );
  if ( sts ) {
    printf("sha256_struct_stat: sha256_block failed with errno = %d\n",sts);
    exit(0);
  }
  
  return 0;
}

