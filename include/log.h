#ifndef __LOG__
#define __LOG__

/* Provides access to POSIX specific high resolution clocks */
#undef  _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L

#include <time.h>
#include <stdio.h>

#define NAME_LEN 32

#ifndef HIGH_RES_TIME
#    ifdef CLOCK_PROCESS_CPUTIME_ID
#        define HIGH_RES_TIME 1
#    else
#        define HIGH_RES_TIME 0
#    endif
#endif

FILE * createLog(const char * salt, const char * start, int startLen,
                 const char * end);
void logProgress(FILE * log, const char * msg);
void logPasswd(FILE * log, const char * passwd, const char * hash);
#if HIGH_RES_TIME
void finalReport(struct timespec start, time_t realtime, long int perms,
                 int passwdCount, int hashCount, FILE * file);
#else
void finalReport(time_t realtime, long int perms, int passwdCount,
                 int hashCount, FILE * file);
#endif
void passwdDump(const char * hashes, int hashLen, const char * passwds,
                int passLen, FILE * file);

#endif /* log.h */
