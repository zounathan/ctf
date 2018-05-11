
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
    * Go to the directory containing the source, and compile. There are compiled binary in directorys Bin32 and Bin64.
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
* Use WinAFL<br>
    * Make sure your target is running correctly without instrumentations.
    * Locate the function you want to fuzz. Note the offset of the function from the start of the module. 
    * Make sure that the target is running correctly under DynamoRIO. For this purpose you can use the standalone debug mode of WinAFL client which does not require connecting to afl-fuzz. Make sure you use the drrun.exe and winafl.dll version which corresponds to your target (32 vs. 64 bit).
        ```
        path\to\DynamoRIO\bin64\drrun.exe -c winafl.dll -debug
        -target_module test_gdiplus.exe -target_offset 0x1270 -fuzz_iterations 10
        -nargs 2 -- test_gdiplus.exe input.bmp
        ```
        You should see the output corresponding to your target function being run 10 times after which the target executable will exit. A .log file should be created in the current directory. The log file contains useful information such as the files and modules loaded by the target as well as the dump of AFL coverage map. In the log you should see pre_fuzz_handler and post_fuzz_handler being run exactly 10 times as well as your input file being open in each iteration. Note the list of loaded modules for setting the -coverage_module flag. Note that you must use the same values for module names as seen in the log file (not case sensitive).
    * Now you should be ready to fuzz the target. First, make sure that both afl-fuzz.exe and winafl.dll are in the current directory. As stated earlier, the command line for afl-fuzz on Windows is:
        ```
        afl-fuzz [afl options] -- [instrumentation options] -- target_cmd_line
        ```
        The following afl-fuzz options are supported. Refer to the original AFL documentation for more info on these flags.
        ```
        -i dir        - input directory with test cases
        -o dir        - output directory for fuzzer findings
        -D dir        - directory containing DynamoRIO binaries (drrun, drconfig)
        -t msec       - timeout for each run
        -f file       - location read by the fuzzed program
        -M \\ -S id   - distributed mode
        -x dir        - optional fuzzer dictionary
        -m limit      - memory limit for the target process
        ```

# AFL Unicorn
[Download](https://github.com/tigerpulma/Afl_unicorn)
[Unicorn-The ultimate CPU emulator](http://www.unicorn-engine.org/)
* build and add in the Unicorn Mode 
    ```
    $ ./build_unicorn_support.sh
    ```
* dump the memory, create the python file to init the target program
* fuzz with the commandline
    ```
    $ afl-fuzz -U -m none -i /path/to/inputs -o /path/to/results -- python temp.py ./test_harness @@
    ```

# AFL Network
[Download](https://github.com/nnamon/afl-network-harness)

# TriforceAFL
Run AFL on linux kernel<br>
[TriforceAFL](https://github.com/nccgroup/TriforceAFL)<br>
[TriforceLinuxSyscallFuzzer](https://github.com/nccgroup/TriforceLinuxSyscallFuzzer/blob/master/runFuzz)
