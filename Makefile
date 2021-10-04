.PHONY: all clean clean_log test unittest memtest

# Set shell to bash for recipes
SHELL = /bin/bash

# Colours
COL_GRN := $(shell tput setaf 2)
COL_RST := $(shell tput sgr0)

# C related flags
CC = gcc
CFLAGS = -iquote include -ansi -Wall -Wextra -pedantic -Wformat=2 \
		   -W -Wshadow -Wstrict-prototypes -Wold-style-definition
LIBS = -lcrypto

# List of executables
EXES = crack md5crypt permutate readShadow

# Tool and flags for doing memory testing, usually valgrind
MEMCHECK = valgrind --tool=memcheck
MEM_FLAGS = --leak-check=full --errors-for-leak-kinds=all \
			--error-exitcode=1 --show-leak-kinds=all -q

# Flags that get set based on the value of DEBUG on build
DEBUG_FLAGS = -D DEBUG -Og -g
NON_DEBUG_FLAGS = -O3

ifdef DEBUG
ifeq ($(DEBUG),true)
CFLAGS += $(DEBUG_FLAGS)
else ifeq ($(DEBUG),1)
CFLAGS += $(DEBUG_FLAGS)
else
CFLAGS += $(NON_DEBUG_FLAGS)
endif
else
CFLAGS += $(NON_DEBUG_FLAGS)
endif

# Tool for md5crypt hashing
MD5PASS = md5pass

# Salt used when hashing
TEST_SALT = hfT7jp2q

# Temporary directory for tests
TMP_DIR = tmp_dir.$(TEST_SALT)

# Test Input/Output
MD5_INPUT = czormg $(TEST_SALT)
MD5_OUTPUT = $$1$$hfT7jp2q$$rhb3sPONC2VlUS2CG4JFe0

PERM_INPUT = xyzab 5
PERM_OUTPUT = "xyzab\nyyzab\nzyzab\nazzab\nbzzab\n"
PERM_CMD = echo {a..z}{a..z}{a..z}{a..z} | tr ' ' '\n' | rev

HASH_INPUT = echo {l,s}{a..z}
HASH_CMD = $(HASH_INPUT) | xargs -d ' ' -i $(MD5PASS) {} $(TEST_SALT)

# Make Recipes
all: $(EXES)

crack: main.c md5crypt.c utils.c log.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

md5crypt: hash.c md5crypt.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

permutate: permutate.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

readShadow: shadow.c md5crypt.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test: unittest memtest

unittest: md5crypt permutate readShadow
	./$< $(MD5_INPUT) | diff <(echo '$(MD5_OUTPUT)') -
	@echo "$(COL_GRN)$(basename $<) hashed $(firstword $(MD5_INPUT))"\
		"correctly$(COL_RST)"
	./$(word 2,$^) $(PERM_INPUT) | diff <(printf $(PERM_OUTPUT)) -
	@echo "$(COL_GRN)$(basename $(word 2,$^)) permutated"\
		"$(firstword $(PERM_INPUT)) correctly$(COL_RST)"
	./$(word 2,$^) aaaa | diff <($(PERM_CMD)) -
	@echo "$(COL_GRN)$(basename $(word 2,$^)) permutated aaaa to zzzz"\
		"correctly$(COL_RST)"
	mkdir $(TMP_DIR) 1>/dev/null 2>&1 || true
	cd $(TMP_DIR); \
	printf "$$($(HASH_CMD))\n$$($(MD5PASS) aa xxxxxxxx)\n" | \
	../$(word 3,$^) $(TEST_SALT) | \
	diff <($(HASH_CMD) | sed -e 's/\$$1\$$.*\$$//') -
	@echo "$(COL_GRN)$(basename $(word 3,$^)) found all hashes"\
		"correctly$(COL_RST)"
	rm -rf $(TMP_DIR)
	@echo

memtest: md5crypt permutate readShadow
	$(MEMCHECK) $(MEM_FLAGS) ./$< $(MD5_INPUT) 1>/dev/null 2>&1
	@echo "$(COL_GRN)$(basename $<) had no memory errors$(COL_RST)"
	$(MEMCHECK) $(MEM_FLAGS) ./$(word 2,$^) $(PERM_INPUT) 1>/dev/null 2>&1
	$(MEMCHECK) $(MEM_FLAGS) ./$(word 2,$^) aaaa 1>/dev/null 2>&1
	@echo "$(COL_GRN)$(basename $(word 2,$^)) had no memory errors$(COL_RST)"
	mkdir $(TMP_DIR) 1>/dev/null 2>&1 || true
	cd $(TMP_DIR); \
	printf "$$($(HASH_CMD))\n$$($(MD5PASS) aa xxxxxxxx)\n" | \
	$(MEMCHECK) $(MEM_FLAGS) ../$(word 3,$^) $(TEST_SALT) 1>/dev/null 2>&1
	@echo "$(COL_GRN)$(basename $(word 3,$^)) had no memory errors$(COL_RST)"
	rm -rf $(TMP_DIR)
	@echo

clean:
	rm -f $(EXES)
	rm -rf $(TMP_DIR)

clean_log:
	rm -f *.log
