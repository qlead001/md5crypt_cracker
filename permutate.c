#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "utils.h"
#include "md5crypt.h"

int main(int argc, char ** argv) {
    int cont = 1;
    int passwdLen, arg2Len = -1;
    long int i, permutations = LONG_MAX;
    char * tail;

    /* Argument Parsing */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s START [END | NUM]\n", argv[0]);
        return 1;
    }

    passwdLen = strlen(argv[1]);

    if (!isLower(argv[1])) {
        fputs("Error: Password must be all lowercase\n", stderr);
        return 1;
    }
    if (argc > 2) {
        arg2Len = strlen(argv[2]);
        if (arg2Len == passwdLen && isLower(argv[2])) {
            permutations = permDiff(argv[1], argv[2]);

            if (permutations < 0) {
                tail = argv[1];
                argv[1] = argv[2];
                argv[2] = tail;
    
                permutations = -permutations;
            }
        } else {
            permutations = (int)strtol(argv[2], &tail, 0);
            if (arg2Len != tail - argv[2]) {
                fprintf(stderr, "Error: %s is not a valid number\n",
                        argv[2]);
                return 1;
            }
        }
    }

    /* Iterate through and print permutations */
    for (i = 0; i < permutations && cont; i++) {
        puts(argv[1]);
        cont = permutate(argv[1]);
    }

    return 0;
}
