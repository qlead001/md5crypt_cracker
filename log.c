#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5crypt.h"


/* TODO: Check for off by one error */
FILE * createLog(const char * salt, const char * start, int startLen,
                 const char * end) {
    char name[NAME_LEN];
    int len = 0;

    memcpy(name, salt, SALT_LEN);
    len += SALT_LEN;
    name[len++] = '_';

    memcpy(name + len, start, startLen);
    len += startLen;
    name[len++] = '_';

    while (len < NAME_LEN - 5 && *end != '\0') {
        name[len++] = *end++;
    }
    memcpy(name + len, ".log", 5);

    return fopen(name, "a");
}

void logProgress(FILE * log, const char * msg) {
    fprintf(log, "[%ld] %s\n", time(NULL), msg);
    fflush(log);
}

void logPasswd(FILE * log, const char * passwd, const char * hash) {
    fprintf(log, "[%ld] Password: %s, Hash: %s\n", time(NULL), passwd, hash);
    fflush(log);
}

void fprintDuration(FILE * file, time_t secs, int nsecs) {
    int i, isFirst = 1;
    long int time[6];
    static const int div[4] = {3600 * 24 * 365, 3600 * 24, 3600, 60};
    static const char * word[6] = {"year", "day", "hour", "minute",
                      "second", "nanosecond"};

    time[5] = nsecs;
    time[4] = secs;
    for (i = 0; i < 4; i++) {
        time[i] = time[4] / div[i];
        time[4] %= div[i];
    }

    for (i = 0; i < 6; i++) {
        if (time[i] > 0) {
	    if (isFirst) {
                isFirst = 0;
            } else {
                fputc(' ', file);
            }
            fprintf(file, "%ld %s", time[i], word[i]);
        }
	if (time[i] > 1) {
            fputc('s', file);
        }
    }
}

#if HIGH_RES_TIME
void finalReport(struct timespec start, time_t realtime, long int perms,
                 int passwdCount, int hashCount, FILE * file) {
#else
void finalReport(time_t realtime, long int perms, int passwdCount,
                 int hashCount, FILE * file) {
#endif
    time_t diff_time;
#if HIGH_RES_TIME
    time_t diff_sec;
    int diff_nsec;
    struct timespec end;
#endif

#if HIGH_RES_TIME
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
#endif
    time(&diff_time);

#if HIGH_RES_TIME
    diff_sec = difftime(end.tv_sec, start.tv_sec);
    diff_nsec = end.tv_nsec - start.tv_sec;
    if (diff_nsec < 0) {
        diff_nsec += 1000000000;
	diff_sec--;
    }
#endif
    diff_time = difftime(diff_time, realtime);

    fprintf(file, "Passwords Hashed: %ld\n", perms);
    fprintf(file, "Hashes Cracked: %d out of %d\n", passwdCount, hashCount);

#if HIGH_RES_TIME
    fputs("Running Time(CPU): ", file);
    fprintDuration(file, diff_sec, diff_nsec);
    fprintf(file, "\nAverage Throughput(CPU): %Lf passwords per second\n",
            (long double)perms / ((long double)diff_sec +
                (long double)diff_nsec / 1.0e9L));
#endif

    fputs("Running Time(Wall): ", file);
    fprintDuration(file, diff_time, 0);
    fprintf(file, "\nAverage Throughput(Wall): %Lf passwords per second\n",
            (long double)perms / (long double)diff_time);

    fflush(file);
}

void passwdDump(const char * hashes, int hashLen, const char * passwds,
                int passLen, FILE * file) {
    int i;
    const int passPad = (passLen > 4) ? passLen : 4;
    const int hashPad = (CRYPT_LEN > 4) ? CRYPT_LEN : 4;

    /*
    fputs("\nHash", file);
    for (i = 0; i < hashPad - 4; i++) {
        fputc(' ', file);
    }
    fputs("   Pass\n", file);
    */
    fprintf(file, "\n%-*s | Pass\n", hashPad, "Hash");
    for (i = 0; i < hashPad + passPad + 3; i++) {
        fputc((i == hashPad + 1) ? '+' : '-', file);
    }
    fputc('\n', file);

    for (i = 0; i < hashLen; i++) {
        if (passwds[i * (passLen + 1)] != '\0') {
            fprintf(file, "%-*s | %s\n", hashPad, hashes + i *
                    (CRYPT_LEN + 1), passwds + i * (passLen + 1));
            /*
            fputs(hashes + i * (CRYPT_LEN + 1), file);
            for (j = 0; j < hashPad - CRYPT_LEN; j++) {
                fputc(' ', file);
            }
            fputs(" | ", file);

            fputs(passwds + i * (passLen + 1), file);
            fputc('\n', file);
	    */
        }
    }
    fflush(file);
}
