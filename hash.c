#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5crypt.h"

int main(int argc, char ** argv) {
    char * output;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s PASSWD SALT\n", argv[0]);
        return 1;
    }
    if (strlen(argv[2]) != SALT_LEN) {
        fprintf(stderr, "Error: Salt must be %d characters long\n", SALT_LEN);
        return 1;
    }

    output = md5crypt(argv[1], strlen(argv[1]), argv[2]);
    printf(MAGIC"%s$%s\n", argv[2], output);
    free(output);
    return 0;
}
