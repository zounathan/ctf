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
* [free chunk](https://github.com/zounathtan/ctf/blob/master/tips/Heap/heap.md#free)
## unsafe unlink
* [2014 HITCON CTF stkof](https://blog.csdn.net/qq_33528164/article/details/79586902)
## safe unlink
* [2015 0ctf freenote](https://kitctf.de/writeups/0ctf2015/freenote)

# off-by-one
* [off-by-one](https://en.wikipedia.org/wiki/Off-by-one_error)
* [off-by-one types](https://www.anquanke.com/post/id/84752)
  * chunk overlapping
    * off-by-one overwrite allocated
    * off-by-one overwrite freed
    * off-by-one null byte
  * unlink
    * off-by-one small bin
    * off-by-one large bin<br>
    
To exploit the off-by-one vulnerability, the chunk size must be `size+0x4(x64 size+0x8)`. Otherwise, the one byte can't rewrite the next chunk's size(inuse)
* [2015 PlaidCTF plaiddb](http://blog.frizn.fr/pctf-2015/pwn-550-plaiddb)

# unsorted bin attack 
Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address.<br>
If the fd of bck is controlled, we can make `*(bck->fd)+0x10=unsorted_chunks(av)`.
```c
/* remove from unsorted list */
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```
* [2016 0ctf zerostorage](http://brieflyx.me/2016/ctf-writeups/0ctf-2016-zerostorage/)

# house of series
* [house of series](https://paper.seebug.org/521/)

# FSOP
* [Advanced Heap Exploitation: File Stream Oriented Programming](https://dangokyo.me/2018/01/01/advanced-heap-exploitation-file-stream-oriented-programming/)
* [play with file_structure](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)
```c
struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags
 
  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
 
  struct _IO_marker *_markers;
 
  struct _IO_FILE *_chain;
 
  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */
 
#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
 
  /*  char* _save_gptr;  char* _save_egptr; */
 
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
## _IO_list_all
* [2016 HITCON house of orange]()
* [2018 0ctf babyheap]()
## _IO_buf_end
* [2017 HITCON ghost in heap]()