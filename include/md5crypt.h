#ifndef __MD5CRYPT__
#define __MD5CRYPT__

#define MD5_LEN 16
#define SALT_LEN 8
#define CRYPT_LEN 22

#define MAGIC "$1$"
#define MAGIC_LEN 3

char * md5crypt(const char * passwd, int passwdLen, const char * salt);

#endif /* md5crypt.h */
