#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>

#include "md5crypt.h"

/* Computes the md5crypt hash of a given password and salt
 * with a magic value of "1"
 *
 * # Parameters
 *   out
 *     buffer of size CRYPT_LEN + 1 to store the hash in
 *   passwd
 *     any char array with length passwdLen
 *   passwdLen
 *     assumed to be less than MD5_LEN which defaults
 *     to a value of 16
 *   salt
 *     assumed to be SALT_LEN in length which is 8
 *
 * # Return Value
 *   A pointer to the base64 encoded hash stored in out
 */
char * md5crypt(char * out, const char * passwd, int passwdLen,
                const char * salt) {
    static const char * b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"\
                        "abcdefghijklmnopqrstuvwxyz";

    int i, j, num;
    MD5_CTX ctx1, ctx2;
    unsigned char digest[MD5_LEN];

    MD5_Init(&ctx1);
    MD5_Update(&ctx1, passwd, passwdLen);
    MD5_Update(&ctx1, MAGIC, MAGIC_LEN);
    MD5_Update(&ctx1, salt, SALT_LEN);

    MD5_Init(&ctx2);
    MD5_Update(&ctx2, passwd, passwdLen);
    MD5_Update(&ctx2, salt, SALT_LEN);
    MD5_Update(&ctx2, passwd, passwdLen);
    MD5_Final(digest, &ctx2);

    /* Assumes that passwdLen is less than MD5_LEN */
    MD5_Update(&ctx1, digest, passwdLen);

    for(i = passwdLen; i; i >>= 1) {
        MD5_Update(&ctx1, (i & 1) ? "\0" : passwd, 1);
    }
    MD5_Final(digest, &ctx1);

    for(i = 0; i < 1000; i++) {
        MD5_Init(&ctx2);
        if (i & 1) {
            MD5_Update(&ctx2, passwd, passwdLen);
        } else {
            MD5_Update(&ctx2, digest, MD5_LEN);
        }
        if (i % 3) {
            MD5_Update(&ctx2, salt, SALT_LEN);
        }
        if (i % 7) {
            MD5_Update(&ctx2, passwd, passwdLen);
        }
        if (i & 1) {
            MD5_Update(&ctx2, digest, MD5_LEN);
        } else {
            MD5_Update(&ctx2, passwd, passwdLen);
        }
        MD5_Final(digest, &ctx2);
    }

    for (i = 0; i < 5; i++) {
        num = digest[i] << 16 | digest[i+6] << 8 | digest[(i<4) ? i+12 : 5];
        for (j = 0; j < 4; j++) {
            out[i*4 + j] = b64[num & 0x3f];
	    num >>= 6;
	}
    }
    out[i*4] = b64[digest[11] & 0x3f];
    out[i*4 + 1] = b64[(digest[11]>>6) & 0x3f];

    out[i*4 + 2] = '\0';

    return out;
}
