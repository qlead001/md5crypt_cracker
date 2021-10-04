#ifndef __UTILS__
#define __UTILS__

#define SHADOW_FILE "etc_shadow"
#define SHADOW_ALT  "shadow"

#define LINE_BUF 128
#define HASH_BUF 128

int permutate(char * str);
long int permDiff(const char * start, const char * end);

int isLower(const char * str);

int readHashes(char ** hashes, const char * salt);
int checkHashes(const char * hashes, int len, const char * hash);

#endif /* utils.h */
