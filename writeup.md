# Password

[REDACTED]

# Source Code

Utils.c holds code for reading and checking the hashes as well as generating
permutations. Log.c holds code for creating and writing a log of progress.
Md5crypt.c holds the md5crypt function.

The only non-standard library code used is openssl/md5 which is available on
most linux systems through the libssl and libssl-dev packages. To link with
this library GCC can take a `-lcrypto` flag.

Command for compiling:
```
gcc -O3 -o crack main.c md5crypt.c utils.c log.c -lcrypto
```

# Number of Threads / Processes

I wrote this as a single threaded program and then I ran program three
times in parallel using `./crack 4fTgjp6q aaaaaa ririri & ./crack 4fTgjp6q
ririri iririr & ./crack 4fTgjp6q iririr`. So I ran a total of three processes.

# CPU Model

AMD Athlon X4 860K Quad Core Processor

# Throughput

Included in this archive is the log files that were generated by the cracking
process. Each log ends with a summary of various statistics about the run.

## Process 1

- Passwords Hashed: 102971925
- Running Time: 6 hours 41 minutes 25 seconds
- Average Throughput: 4275.354993 passwords per second

## Process 2

- Passwords Hashed: 102971925
- Running Time: 6 hours 14 minutes 14 seconds
- Average Throughput: 4585.905629 passwords per second

## Process 3

- Passwords Hashed: 102971926
- Running Time: 6 hours 51 minutes 53 seconds
- Average Throughput: 4166.710881 passwords per second
