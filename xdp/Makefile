# Явно clang (не ?=, т.к. make имеет встроенный CC=cc)
CC      := clang
CFLAGS  := -O2 -g -Wall -target bpf \
           -I/usr/include/x86_64-linux-gnu \
           -I/usr/include/bpf \
           -D__TARGET_ARCH_x86

OBJS := xdp_ddos_protect.o

.PHONY: all clean

all: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) *.ll
