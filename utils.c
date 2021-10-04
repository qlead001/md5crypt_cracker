#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5crypt.h"

#include "utils.h"

int permutate(char * str) {
    int index = 0;

    while (1) {
        if (str[index] == 'z') {
            str[index++] = 'a';
	} else if (str[index] == '\0') {
            return 0;
        } else {
            str[index]++;
	    return 1;
        }
    }
}

long int permDiff(const char * start, const char * end) {
    int index = 0;
    long int diff = 0;
    long int mult = 1;

    while (start[index]) {
        diff += (end[index] - start[index]) * mult;
        mult *= 26;
        index++;
    }

    return diff;
}

int isLower(const char * str) {
    char c;

    while ((c = *str++)) {
        if (c < 'a' || c > 'z') {
            return 0;
        }
    }

    return 1;
}

int readHashes(char ** hashes, const char * salt) {
    int len = 0;
    char buf[LINE_BUF], * hash;
    FILE * in;
    char start[MAGIC_LEN + SALT_LEN + 2] = MAGIC;

    memcpy(start + MAGIC_LEN, salt, SALT_LEN);
    start[MAGIC_LEN + SALT_LEN] = '$';
    start[MAGIC_LEN + SALT_LEN + 1] = '\0';

    *hashes = (char *)malloc(sizeof(char) * (HASH_BUF * (CRYPT_LEN + 1)));
    if (*hashes == NULL) {
        fputs("Error: Allocation failed\n", stderr);
        return -1;
    }

    /* Get file handle for shadow file or stdin if neither
     * file can be found in the local directory
     */
    if ((in = fopen(SHADOW_FILE, "r")) == NULL &&
        (in = fopen(SHADOW_ALT, "r")) == NULL) {
        in = stdin;
    }

    while (!feof(in) && len < HASH_BUF) {
        if (fgets(buf, LINE_BUF, in) == NULL) {
            if (ferror(in)) {
                perror("Read Error");
		len = -1;
		break;
            } else {
                continue;
            }
        }

        if ((hash = strstr(buf, start)) != NULL) {
            memcpy(*hashes + len++ * (CRYPT_LEN + 1),
                    hash + MAGIC_LEN + SALT_LEN + 1, CRYPT_LEN);
            (*hashes)[len * (CRYPT_LEN + 1) - 1] = '\0';
        }
    }

    if (in != stdin) {
        fclose(in);
    }

    return len;
}

int checkHashes(const char * hashes, int len, const char * hash) {
    int i;

    for (i = 0; i < len; i++) {
        if (strcmp(hash, hashes + i * (CRYPT_LEN + 1)) == 0) {
            return i;
        }
    }

    return -1;
}
