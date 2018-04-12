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
* [free chunk](./heap.md#free)
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
## off-by-one overwrite allocated
```
/* A has off-by-one error, B and C are allocated */
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      A        |      B      |      C      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ```
1. off-by-one rewrite the size of B, size(B)=size(B+C), keep pre_inuse=1
2. free(B)
3. malloc(size(B+C))
## off-by-one overwrite freed
```
/* A has off-by-one error, B is freed, C is allocated */
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      A        |      B      |      C      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ```
1. off-by-one rewrite the size of B, size(B)=size(B+C), keep pre_inuse=1
2. malloc(size(B+C))
## off-by-one null byte
```
/* A has off-by-one error, B and C are allocated */
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      A        |      B      |      C      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ```
1. contruct fake fd and bk in chunk A
2. off-by-one rewrite pre_inuse=0, keep the size(B) unchanged. (or change size(B), and construct the chunk foot.)
2. free(B), unlink chunk A
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
## house of prime

## house of mind
* [house of mind](https://sploitfun.wordpress.com/2015/03/04/heap-overflow-using-malloc-maleficarum/)
1. tricks ‘glibc malloc’ to use a fake arena
2. Fake Arena is constructed in such a way that `unsorted bin’s fd` contains the address of `GOT entry of function – 12`.
3. Thus now when vulnerable program free’s a chunk GOT entry of function is overwritten with shellcode address.
* Prerequisites
  * A series of malloc calls is required until a chunk’s address – when aligned to a multiple of HEAP_MAX_SIZE results in a memory area which is controlled by the attacker. This is the memory area where fake heap_info structure is found. Fake heap_info’s arena pointer ar_ptr would point to fake arena. Thus both fake arena and fake heap_info’s memory region would be controlled by the attacker.
  * A chunk whose size field (and its arena pointer – prereq 1) controlled by the attacker should be freed.
  * Chunk next to the above freed chunk should not be a top chunk.
```c
vuln.c
int main (void) {
 char *ptr = malloc(1024); /* First allocated chunk */
 char *ptr2; /* Second chunk/Last but one chunk */
 char *ptr3; /* Last chunk */
 int heap = (int)ptr & 0xFFF00000;
 _Bool found = 0;
 int i = 2;

 for (i = 2; i < 1024; i++) {
   /* Prereq 1: Series of malloc calls until a chunk's address - when aligned to HEAP_MAX_SIZE results in 0x08100000 */
   /* 0x08100000 is the place where fake heap_info structure is found. */
   if (!found && (((int)(ptr2 = malloc(1024)) & 0xFFF00000) == (heap + 0x100000))) {
     printf("good heap allignment found on malloc() %i (%p)\n", i, ptr2);
     found = 1;
     break;
   }
 }
 ptr3 = malloc(1024); /* Last chunk. Prereq 3: Next chunk to ptr2 != av->top */
 /* User Input. */
 fread (ptr, 1024 * 1024, 1, stdin);

 free(ptr2); /* Prereq 2: Freeing a chunk whose size and its arena pointer is controlled by the attacker. */
 free(ptr3); /* Shell code execution. */
 return(0); /* Bye */
}
```
![](https://docs.google.com/drawings/d/1--VLWTMBoF1RMNTchYu5EFScxGBSw1MovyOi656tgow/pub?w=721&h=834)<br>

glibc malloc does the following, when `free(ptr2)` of vulnerable program gets executed
* Arena for the chunk that is getting freed is retrieved by invoking `arena_for_chunk` macro.
```c
#define HEAP_MAX_SIZE (1024*1024) /* must be a power of two */

#define heap_for_ptr(ptr) \
 ((heap_info *)((unsigned long)(ptr) & ~(HEAP_MAX_SIZE-1)))

/* check for chunk from non-main arena */
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)

#define arena_for_chunk(ptr) \
 (chunk_non_main_arena(ptr) ? heap_for_ptr(ptr)->ar_ptr : &main_arena)
```
* fake arena and chunk address are passed as arguments to `_int_free`.Following are the mandatory fields of fake arena that needs to be overwritten by the attacker
  * Mutex – It should be in unlocked state.
  * Bins – Unsorted bin’s fd should contain the address of GOT entry of free – 12.
  * Top –
    * Top address should not be equal to the chunk address that is getting freed.
    * Top address should be greater than next chunk address.
  * System Memory – System memory should be greater than next chunk size.
* _int_free
  * If chunk is non mmap’d, acquire the lock. 
  * Consolidate:
  * Place the currently freed chunk in unsorted bin. unsorted bin’s fd->bk=ptr2(GOT hijack)<br> 

At present day, house of lore technique doesn't work since ‘glibc malloc’ has got hardened.<br>
Corrupted chunks: Unsorted bin’s first chunk’s bk pointer should point to unsorted bin. If not ‘glibc malloc’ throws up corrupted chunk error.
```c
if (__glibc_unlikely (fwd->bk != bck))
        {
          errstr = "free(): corrupted unsorted chunks";
          goto errout;
        }
```  
* [bypass the corrupted chunks](https://gbmaster.wordpress.com/2015/06/15/x86-exploitation-101-house-of-mind-undead-and-loving-it/)<br>
Fake Arena is constructed in such a way that `fastbin list fd` contains the address of `GOT entry of function`.
```c
set_fastchunks(av);
  fb = &(av->fastbins[fastbin_index(size)]);
  /* Another simple check: make sure the top of the bin is not the
     record we are going to add (i.e., double free).  */
  if (__builtin_expect (*fb == p, 0))
    {
      errstr = "double free or corruption (fasttop)";
      goto errout;
    }
  p->fd = *fb;
  *fb = p;
```
## house of spirit
1. construct a fake fastbin chunk
2. free the fake fastbin chunk
3. malloc to return the fake fastbin chunk pointer
* [2014 hack.lu CTF OREO](https://blog.betamao.me/2018/02/25/hack-lu-ctf-2014-oreo/)
## house of force
Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer.<br>
`Glibc don't check the size of top chunk`
1. rewrite the top chunk size to 0xffffffff(x86)
2. malloc(0xffe00020)(0xffe00020<0xffffffff)
3. assume the address of top chunk is 0x601200. the new top chunk address is (0xffe00020+0x601200)=`0x401230`
4. the next malloc can return 0x401238
* [2016 BCTF bcloud](https://blog.csdn.net/qq_33528164/article/details/79870585)
## house of einherjar
1. create a fake chunk wherever we want, set fd and bk pointers to point at the fake_chunk in order to pass the unlink checks
2. set the last chunk's pre_inuse to 0
3. rewrite a fake prev_size in the last chunk, so that it will consolidate with our fake chunk.(`pre_size=address(last_chunk)-address(fake_chunk)`)
4. free last chunk, that will consolidate with the fake chunk and top chunk. the top chunk is set to the fake chunk.
* [2016 Seccon tinypad](https://github.com/blendin/writeups/tree/master/2016/tinypad)
## house of lore
Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist.
1. create a fake chunk
2. rewrite the freed smallbin chunk'bk to fake chunk address
3. rewrite the fake chunk's fd to freed smallbin chunk address
4. malloc() twice
```c
static void_t* _int_malloc(mstate av, size_t bytes)
{
[ ... ]
else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;
       [ ... ]
}
```
The same as house of mind, house of lore technique doesn't work.([house of mind](#house-of-mind))
      
## house of orange
[top chunk size is lesser than user requested size](./heap.md#Top chunk)
* [2016 HITCON house of orange]()

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
1. overwrite _IO_list_all with unsorted bin
2. put chunk in small bin[4](size 0x60), or small bin[9](size 0xb0)
3. construct fake vtable->_IO_overflow
4. malloc
* [2016 HITCON house of orange]()<br>

after libc-2.24, vtable check is added. we can't directly construct fake vtable in heap. Instead, we can use `_IO_str_jumps` and `_IO_wstr_jumps` as vtable.
* [2018 0ctf babyheap](/writeups/2018-0ctf/babyheap)
## _IO_buf_end
1. overwrite _IO_buf_end, change the end of stdin buf end.
2. overwrite `_malloc_hook`(_malloc_hook is between stdin buf and main_arena)
3. malloc()
* [2017 HITCON ghost in heap](https://github.com/scwuaptx/CTF/tree/master/2017-writeup/hitcon/ghost_in_the_heap)