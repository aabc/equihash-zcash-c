
BLAKE2_dir = BLAKE2/sse
BLAKE2_imp = blake2b.c
CC         = gcc
CFLAGS     = -g -march=native

equihash: equihash.c
	$(CC) -std=c99 -I$(BLAKE2_dir) $(CFLAGS) -o $@ $< $(BLAKE2_dir)/$(BLAKE2_imp)

clean:
	-rm -f equihash
