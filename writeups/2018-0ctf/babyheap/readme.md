Introduction

I take this challenge as a variation of FSOP (File Stream Oriented Programming). 
The glibc library given in this challenge is already patched with an extra check on the validity of the vtable of fake file stream. 

Vulnerability

There is an one-byte out-of-bound write in the update function. 

Exploitation

With off-by-one, we can leak the heap and libc address.
The problem is how to exploit. we can't leak the mmap address, neither program address.
1, Overwrite the __malloc_hook.
- we can't allocate heap near __malloc_hook. If we use the unsorted bin attack to overwrite IO_buf_end, the function read can't get enough length to overwrite the __malloc_hook
2, House of orange
- To use this method, there are two problems
- How to set the small bin[4](size 0x60)
- bypass the check of vtable

Above all, the final exploit works as below:

(1) Use the one-byte out-of-bound vulnerability to create overlapping chunk. And leak the base address of libc.

(2) Use the consolidation to put heap to small bin[4]

(3) Use update function to overwrite the bk of chunk linked in unsorted bin with &_IO_list_all – 0x10 and trigger the unsorted bin attack.

(4) Create the fake _IO_file struct, and use the _IO_wstr_jumps as vtable to bypass the check.

(5) Trigger abort routine, and execute the onegadget.
