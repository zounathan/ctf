
American Fuzzy Lop
=
# AFL
* AFL Install<br>
    [Download](http://lcamtuf.coredump.cx/afl/)
```
make
make install
```
* Recompile target program<br>
    Recompile the program to inject the instrumentation 
```
CC=afl-gcc ./configure
make
```
* AFL Execute<br>
    make dir for afl's input and output
```
mkdir afl_in afl_out
afl-fuzz -i afl_in -o afl_out ./elf_to_fuzz -a @@
```
# WIN AFL
[Download](https://github.com/ivanfratric/winafl)<br>
Instead of instrumenting the code at compilation time, WinAFL relies on dynamic instrumentation using [DynamoRIO](./DynamoRIO.md) to measure and extract target coverage. 
* Build WinAFL
    * Install [CMake](http://www.cmake.org)
    * Download [Dynamorio](http://dynamorio.org/) and WinAFL
    * Go to the directory containing the source, and compile.
```
# For a 32-bit build
mkdir build32
cd build32
cmake .. -DDynamoRIO_DIR=..\path\to\DynamoRIO\cmake
cmake --build . --config Release

# For a 64-bit build
mkdir build64
cd build64
cmake -G"Visual Studio 10 Win64" .. -DDynamoRIO_DIR=..\path\to\DynamoRIO\cmake
cmake --build . --config Release
```
# AFL Unicorn
[Download](https://github.com/tigerpulma/Afl_unicorn)

# AFL QEMU

# AFL Network
[Download](https://github.com/nnamon/afl-network-harness)
