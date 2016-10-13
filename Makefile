
BLAKE2_dir = BLAKE2/sse
BLAKE2_imp = blake2b.c
CC         = gcc
CFLAGS     = -O3 -march=native

all: basicSolver basicSolver-opt

basicSolver: basicSolver.c
	$(CC) -std=c99 -I$(BLAKE2_dir) $(CFLAGS) -o $@ $< $(BLAKE2_dir)/$(BLAKE2_imp)

basicSolver-opt: basicSolver-opt.c
	$(CC) -std=c99 -I$(BLAKE2_dir) $(CFLAGS) -o $@ $< $(BLAKE2_dir)/$(BLAKE2_imp)

clean:
	-rm -f basicSolver basicSolver-opt
