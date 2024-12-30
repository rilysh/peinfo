CC ?= clang
CFLAGS = -Wall -Wextra
PROGRAM = peinfo

ifeq ($(DEBUG),yes)
	CFLAGS += -ggdb3
else
	CFLAGS += -O2 -s
endif

all:
	$(CC) $(CFLAGS) -o $(PROGRAM) $(PROGRAM).c

clean:
	rm -f $(PROGRAM)
