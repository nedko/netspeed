CFLAGS := -Wall -Wextra
CFLAGS += -Werror
CFLAGS += -O2
#CFLAGS += -O0 -g

netspeed: netspeed.c GNUmakefile
	gcc $(CFLAGS) netspeed.c -o netspeed

.PHONY: clean
clean:
	rm -fv netspeed

.PHONY: run
run: netspeed
	./netspeed d speedtest.mtel.bg
