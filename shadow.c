#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "md5crypt.h"

int main(int argc, char ** argv) {
    char * hashes;
    int i, len;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s SALT\n", argv[0]);
        return 1;
    }
    if (strlen(argv[1]) != SALT_LEN) {
        fprintf(stderr, "Error: Salt must be %d characters long\n", SALT_LEN);
        return 1;
    }

    len = readHashes(&hashes, argv[1]);

    for (i = 0; i < len; i++) {
        puts(hashes + i * (CRYPT_LEN + 1));
    }

    free(hashes);
    return len < 0;
}
