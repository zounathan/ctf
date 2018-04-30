
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
[Download](https://github.com/ivanfratric/winafl)

# AFL Unicorn
[Download](https://github.com/tigerpulma/Afl_unicorn)

# AFL QEMU

# AFL Network
