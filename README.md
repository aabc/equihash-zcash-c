# Equihash Solver for Zcash, C Implementation

## Install
```
git clone https://github.com/aabc/equihash-zcash-c.git
cd equihash-zcash-c
git submodule init
git submodule update
make
./basicSolver -n 96 -k 5 -I 'block header' -N 0
./basicSolver-opt -n 200 -k 9 -I 'block header' -N 1
```
You can use Zcash Solver CLI API:
```
./basicSolver-opt -n 200 -k 9 -i input.bin
```
