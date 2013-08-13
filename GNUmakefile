OS := $(shell uname -s)
CFLAGS := -Wall -Wextra
CFLAGS += -Werror
CFLAGS += -O2
#CFLAGS += -O0 -g

ifneq ($(OS),Linux)
CFLAGS += -DNO_SCHED_FIFO=1
endif

netspeed: netspeed.c GNUmakefile
	gcc $(CFLAGS) netspeed.c -o netspeed

.PHONY: clean
clean:
	rm -fv netspeed

.PHONY: run
run: netspeed
	./netspeed d speedtest.mtel.bg
