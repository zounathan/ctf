Heap Skills
=
Unlike stack overflow, heap overflow can't directly control EIP.<br>
Here are some methods to control flow
* allocte stack memorty, overwrite EIP
* GOT hijack
* fake vtable (FOSP File Stream Oriented Programming)

# fastbin attack
1. allocte two fastbin
2. heap overflow rewrite the fd
3. fake chunk
4. malloc
* Don't check the alignment. We can construct fake chunk in any memorty position.
```c
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
...
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
  {
    errstr = "malloc(): memory corruption (fast)";
```
* [2017 0ctf babyheap](https://blog.csdn.net/qq_29343201/article/details/66476135)

# fastbin duplication
* If we free the fastchunk that at the top of fastbin list, the program will crash.
* we can double free the fastchunk, if it's not at the top of fastbin list. Then, the chunk put into the fastbin again.
```c
int *a = malloc(8);
int *b = malloc(8);
int *c = malloc(8);
free(a);
/* if free(a), crash */
free(b);
free(a);
```
## fastbin_dup_consolidate
Tricking malloc into returning an already-allocated heap pointer by putting a pointer on both fastbin freelist and unsorted bin freelist.
```c
void* p1 = malloc(0x40);
void* p2 = malloc(0x40);
free(p1);
/* Allocated large bin to trigger malloc_consolidate */
/* In malloc_consolidate(), p1 is moved to the unsorted bin */
void* p3 = malloc(0x400);
/* Trigger the double free vulnerability */
/* p1 is in unsorted bin and fast bin */
free(p1);
```

# unlink
Exploiting free on a corrupted chunk to get arbitrary write.
[free chunk](https://github.com/zounathtan/ctf/blob/master/tips/heap.md#free)
## unsafe unlink
* [2014 HITCON CTF stkof](https://blog.csdn.net/qq_33528164/article/details/79586902)
## safe unlink
* [2015 0ctf freenote](https://kitctf.de/writeups/0ctf2015/freenote)

# off-by-one

# unsorted bin attack 
