#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "utils.h"
#include "md5crypt.h"

/* Sets how often to save progress */
#ifndef CHECKPOINT
#    define CHECKPOINT 200000
#endif

int main(int argc, char ** argv) {
    /* Local Variables */
    int passwdLen, arg3Len = -1;
    int index, len, count = 0;
    int cont = 1;
    long int i, permutations = LONG_MAX;
    char * tail;
    char * hash, * hashes;
    char * passwds;
    FILE * log;
    time_t realtime;
#if HIGH_RES_TIME
    struct timespec start;
#endif

    /* Argument Parsing */
    if (argc < 3) {
        fprintf(stderr, "Usage: %s SALT START [END | NUM]\n", argv[0]);
        return 1;
    }
    if (strlen(argv[1]) != SALT_LEN) {
        fprintf(stderr, "Error: Salt must be %d characters long\n", SALT_LEN);
        return 1;
    }

    passwdLen = strlen(argv[2]);

    if (passwdLen > MD5_LEN) {
        fprintf(stderr, "Error: Password must be no more than %d "\
                        "characters long\n", MD5_LEN);
        return 1;
    }
    if (!isLower(argv[2])) {
        fputs("Error: Password must be all lowercase\n", stderr);
        return 1;
    }
    if (argc > 3) {
        arg3Len = strlen(argv[3]);
        if (arg3Len == passwdLen && isLower(argv[3])) {
            permutations = permDiff(argv[2], argv[3]);

	    /* Swap start and end strings if they are reversed */
            if (permutations < 0) {
                tail = argv[2];
                argv[2] = argv[3];
                argv[3] = tail;
    
                permutations = -permutations;
            }
        } else {
            permutations = (int)strtol(argv[3], &tail, 0);
            if (arg3Len != tail - argv[3]) {
                fprintf(stderr, "Error: %s is not a valid number\n",
                        argv[3]);
                return 1;
            }
        }
    }

    /* Read hashes and end early if there are none */
    len = readHashes(&hashes, argv[1]);
    if (len < 0) {
        fprintf(stderr, "Error: No hashes found with the salt %s\n",
                argv[1]);
	free(hashes);
	return 1;
    }

    passwds = (char *)calloc(HASH_BUF, sizeof(char) * (passwdLen + 1));
    if (passwds == NULL) {
        fputs("Error: Allocation failed\n", stderr);
	free(hashes);
        return 1;
    }

    log = createLog(argv[1], argv[2], passwdLen,
                    (argc >= 4) ? argv[3] : "all");
    if (log == NULL) {
        fputs("Error: Failed to open log file\n", stderr);
	free(hashes);
	free(passwds);
        return 1;
    }

    hash = (char *)malloc(sizeof(char) * (CRYPT_LEN + 1));
    if (hash == NULL) {
        fputs("Error: Allocation failed\n", stderr);
	free(hashes);
	free(passwds);
        return 1;
    }

    time(&realtime);
#if HIGH_RES_TIME
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
#endif

    /* Iterate through and print permutations */
    for (i = 0; i < permutations && cont && count < len; i++) {
        /* Save progress every so often */
        if (i % CHECKPOINT == 0) {
            logProgress(log, argv[2]);
        }

        md5crypt(hash, argv[2], passwdLen, argv[1]);
        if ((index = checkHashes(hashes, len, hash)) != -1) {
            logPasswd(log, argv[2], hash);
            memcpy(passwds + index * (passwdLen + 1), argv[2], passwdLen + 1);
            count++;
        }
        cont = permutate(argv[2]);
    }

    logProgress(log, "COMPLETE");

#if HIGH_RES_TIME
    finalReport(start, realtime, i, count, len, log);
#else
    finalReport(realtime, i, count, len, log);
#endif
    if (count > 0) {
        passwdDump(hashes, len, passwds, passwdLen, log);
    }

    if (log != stdout) {
        fclose(log);

#if HIGH_RES_TIME
        finalReport(start, realtime, i, count, len, stdout);
#else
        finalReport(realtime, i, count, len, stdout);
#endif
        if (count > 0) {
            passwdDump(hashes, len, passwds, passwdLen, stdout);
        }
    }

    free(hashes);
    free(passwds);
    free(hash);
    return 0;
}
