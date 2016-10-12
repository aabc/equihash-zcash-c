
BLAKE2_dir = BLAKE2/sse
BLAKE2_imp = blake2b.c
CC         = gcc
CFLAGS     = -O3 -march=native

all: equihash equihash-opt

equihash: equihash.c
	$(CC) -std=c99 -I$(BLAKE2_dir) $(CFLAGS) -o $@ $< $(BLAKE2_dir)/$(BLAKE2_imp)

equihash-opt: equihash-opt.c
	$(CC) -std=c99 -I$(BLAKE2_dir) $(CFLAGS) -o $@ $< $(BLAKE2_dir)/$(BLAKE2_imp)

clean:
	-rm -f equihash equihash-opt
