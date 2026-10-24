CC := clang
THRESHOLD ?= 100
MAX_SOURCES ?= 4096
WINDOW_NS ?= 1000000000
MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)
ifeq ($(strip $(MULTIARCH)),)
MULTIARCH := $(shell gcc -dumpmachine)
endif
CPPFLAGS += -I/usr/include/$(MULTIARCH) -DMAX_SOURCES=$(MAX_SOURCES) -DTHRESHOLD=$(THRESHOLD) -DWINDOW_NS=$(WINDOW_NS)ULL
CFLAGS := -O2 -g -Wall -Werror -target bpf
.PHONY: all clean
all: xdp_ddos_protect.o
xdp_ddos_protect.o: xdp_ddos_protect.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
clean:
	rm -f xdp_ddos_protect.o
