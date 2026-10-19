CC = clang
CFLAGS = -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu

all: xdp_ddos_protect.o

xdp_ddos_protect.o: xdp_ddos_protect.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o

.PHONY: all clean
