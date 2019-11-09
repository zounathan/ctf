Heap Skills
=
Unlike stack overflow, heap overflow can't directly control EIP.<br>
Here are some methods to control flow
* allocte stack memorty, overwrite EIP
* GOT hijack
* fake vtable (FOSP File Stream Oriented Programming)

# fastbin attack
1. allocte two fastbin
2. free one chunk A
3. heap overflow rewrite the chunk A's fd with `ptr`
4. construct fake chunk with the same size ath position `ptr`
5. malloc twice. Get the chunk at `ptr`
* Don't check the alignment. We can construct fake chunk in any memory position.
* Check the size(4 bytes) of the fake chunk.
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
* If we double free the fastchunk that at the top of fastbin list, the program will crash.
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
1. Free the fastbin to put the chunk in fastbin freelist.
2. Trigger malloc_consolidate to put the chunk in unsorted bin freelist.
3. Double free the fastbin to put the chunk in the fastbin freelist again.
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
```c
#define unlink( P, BK, FD ) {
BK = P->bk;
FD = P->fd;
FD->bk = BK;
BK->fd = FD;
}
```
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
2. off-by-one rewrite pre_inuse=0, presize=size(A), keep the size(B) unchanged. (or change size(B), and construct the chunk foot.)
2. free(B), unlink chunk A
* [2015 PlaidCTF plaiddb](http://blog.frizn.fr/pctf-2015/pwn-550-plaiddb)

# unsorted bin attack 
Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a unsortedbin freelist address into arbitrary address.<br>
If the fd of bck(the bk of the unsorted bin) is controlled, we can make `*(bck->fd)+0x10=unsorted_chunks(av)`.
```c
/* remove from unsorted list */
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```
* [2016 0ctf zerostorage](http://brieflyx.me/2016/ctf-writeups/0ctf-2016-zerostorage/)

# house of series
* [house of series](https://paper.seebug.org/521/)
## house of prime
* [house of prime](https://gbmaster.wordpress.com/2014/08/24/x86-exploitation-101-this-is-the-first-witchy-house/)
1. free chunk A with size of 8 bytes to rewrite `max_fast` in arena
```c
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz)        ((((unsigned int)(sz)) >> 3) - 2)

set_fastchunks(av);
fb = &(av->fastbins[fastbin_index(size)]);
/* Another simple check: make sure the top of the bin is not the record we are going to add (i.e., double free).  */
if (__builtin_expect (*fb == p, 0)){
  errstr = "double free or corruption (fasttop)";
  goto errout;
}
p->fd = *fb;
*fb = p;
```
2. free chunk B to overwrite `arena_key`. (the index must make fastbins[index] pointing to arena_key.)  
    1. `fb` will be set to `arena_key`
    2. `fd` pointer of the chunk B will be set to the `address of the existing arena` 
    3. `arena_key(fb)` will be set to the `address of the chunk B`.
3. malloc
* The `arena_get()` macro is to find the current arena by retrieving the `arena_key` thread specific data, or failing this(arena_key=0), creating a new arena. 
* set `ar_ptr` to the new value of arena_key, the address of `chunk B(fake arena)`. and it's passed to the function _int_malloc() along with the requested allocation size.
```c
Void_t*
public_mALLOc(size_t bytes)
{
    mstate ar_ptr;
    Void_t *victim;
    ...
    arena_get(ar_ptr, bytes);
    if(!ar_ptr)
      return 0;
    victim = _int_malloc(ar_ptr, bytes);
    ...
    return victim;
}
```
* the requested size is smaller than av->max_fast(B->size)
  * By setting up a fake fastbin entry at av->fastbins[fastbin_index(nb)] it is possible to get malloc to return a nearly-arbitrary pointer.
  * Specifically, the size of the victim chunk must have the same fastbin_index() as nb.
```c
Void_t*
_int_malloc(mstate av, size_t bytes)
{
    INTERNAL_SIZE_T nb;               /* normalized request size */
    unsigned int    idx;              /* associated bin index */
    mfastbinptr*    fb;               /* associated fastbin */
    mchunkptr       victim;           /* inspected/selected chunk */

    checked_request2size(bytes, nb);

    if ((unsigned long)(nb) <= (unsigned long)(av->max_fast)) {
      long int idx = fastbin_index(nb);
      fb = &(av->fastbins[idx]);
      if ( (victim = *fb) != 0) {
        if (fastbin_index (chunksize (victim)) != idx)
          malloc_printerr (check_action, "malloc(): memory corruption (fast)", chunk2mem (victim));
        *fb = victim->fd;
        check_remalloced_chunk(av, victim, nb);
        return chunk2mem(victim);
      }
    }
```
* the requested size is bigger than av->max_fast(B->size)
  * victim can be set to an arbitrary address by creating a fake av->bins[0] (ptr1) value. 
    * `victim=ptr1->bk=ptr2`
    * `bck=victim->bk=ptr2->bk`
  * set bck to the address of a GOT-8. This will redirect execution to ptr1, which can safely contain a near jmp to skip past the crafted value at ptr1+0xc.
    * bck->fd = unsorted_chunks(av) => GOT=ptr1(GOT hijack)
    * unsorted_chunks(av)->bk = bck => ptr1+0xc=GOT-8
```c
for(;;) {
      while ( (victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
        bck = victim->bk;
        if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0) || __builtin_expect (victim->size > av->system_mem, 0))
          malloc_printerr (check_action, "malloc(): memory corruption", chunk2mem (victim));
        size = chunksize(victim);
        if (in_smallbin_range(nb) &&
            bck == unsorted_chunks(av) &&
            victim == av->last_remainder &&
            (unsigned long)(size) > (unsigned long)(nb + MINSIZE)) {
          ...
        }
        unsorted_chunks(av)->bk = bck;
        bck->fd = unsorted_chunks(av);
        if (size == nb) {
          ...
          return chunk2mem(victim);
        }
        ...
```        
As the base of this kind of exploit is the `ability to free chunks that are 8 bytes long`, then this whole thing is not working anymore since glibc 2.4.
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
/* Another simple check: make sure the top of the bin is not the record we are going to add (i.e., double free).  */
if (__builtin_expect (*fb == p, 0)){
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
* [2016 HITCON house of orange](https://blog.csdn.net/qq_35519254/article/details/78627056)

# FSOP
* [Advanced Heap Exploitation: File Stream Oriented Programming](https://dangokyo.me/2018/01/01/advanced-heap-exploitation-file-stream-oriented-programming/)
* [play with file_structure](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)
```c
_IO_FILE_plus {
    _flags = 0xfbad2086, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7ffff7b94620 <_IO_2_1_stdout_>, 
    _fileno = 0x2, 
    _flags2 = 0x0, 
    _old_offset = 0xffffffffffffffff, 
    _cur_column = 0x0, 
    _vtable_offset = 0x0, 
    _shortbuf = "", 
    _lock = 0x7ffff7b95770 <_IO_stdfile_2_lock>, 
    _offset = 0xffffffffffffffff, 
    _codecvt = 0x0, 
    _wide_data = 0x7ffff7b93660 <_IO_wide_data_2>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0x0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7b926e0 <_IO_file_jumps>
}
```
the vtable
```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```
## _IO_list_all
1. overwrite _IO_list_all with [unsorted bin attack](#unsorted-bin-attack). Change the _IO_list_all to the unsorted bin (av)
2. put chunk in small bin[4](size 0x60), or small bin[9](size 0xb0)
3. construct fake vtable->_IO_overflow to system("/bin/sh")
4. malloc
when we call the malloc, the system will crash. The glibc will detect memory corruption. At this time, it will flush all the IO stream with function IO_flush_all_lockp.
Because the _IO_list_all is overwritted with unsorted bin (av), it will get the next fp from _IO_list_all->chain, which is the chunk in small bin[4].
Construct the fake _IO_FILE_plus struct in that chunk to make `(fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)` true. 
So it will call `vtable->_IO_OVERFLOW(fp,EOF)`
```c
int _IO_flush_all_lockp (int do_lock){
     int result = 0;
     struct _IO_FILE *fp;
     int last_stamp;
   
   #ifdef _IO_MTSAFE_IO
     __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
     if (do_lock) _IO_lock_lock (list_all_lock);
   #endif
  
     last_stamp = _IO_list_all_stamp;
     fp = (_IO_FILE *) _IO_list_all;
     while (fp != NULL){
         run_fp = fp;
         if (do_lock) _IO_flockfile (fp);
         if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
   #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
          || (_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))
   #endif
          )&& _IO_OVERFLOW (fp, EOF) == EOF)
            result = EOF;
  
         if (do_lock) _IO_funlockfile (fp);
         run_fp = NULL;
   
         if (last_stamp != _IO_list_all_stamp) {
           /* Something was added to the list.  Start all over again.  */
           fp = (_IO_FILE *) _IO_list_all;
           last_stamp = _IO_list_all_stamp;
         }else
           fp = fp->_chain;
}
```       
* [2016 HITCON house of orange](https://blog.csdn.net/qq_35519254/article/details/78627056)<br>

after libc-2.24, vtable check is added. we can't directly construct fake vtable in heap. Instead, we can use `_IO_str_jumps` and `_IO_wstr_jumps` as vtable.
the functions `_IO_str_overflow, _IO_str_finish, _IO_wstr_overflow, _IO_wstr_finish` can be used to call onegadget to get shell.

function _IO_str_overflow will call `(*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size)`.
we can make the `*((_IO_strfile *) fp)->_s._allocate_buffer` to be onegadget.
```c
int _IO_str_overflow (_IO_FILE *fp, int c){
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  ...
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only)){
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
        return EOF;
      else{
        char *new_buf;
        char *old_buf = fp->_IO_buf_base;
        size_t old_blen = _IO_blen (fp);
        _IO_size_t new_size = 2 * old_blen + 100;
        if (new_size < old_blen)
          return EOF;
        new_buf= (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
        ...
}
```
function _IO_str_finish will call `(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base)`.
we can make the `((_IO_strfile *) fp)->_s._free_buffer` to be onegadget.
```c
void _IO_str_finish (_IO_FILE *fp, int dummy){
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
  fp->_IO_buf_base = NULL;
  _IO_default_finish (fp, 0);
}
```
* [2018 0ctf babyheap](/writeups/2018/0ctf/babyheap)
* [2018 MeePwn house of card](/writeups/2018/MeePwn/house_of_card)
## _IO_buf_end
1. overwrite _IO_buf_end with [unsorted bin attack](#unsorted-bin-attack), change the end of stdin buf end to the unsorted bin (av). the buf locates in the `_IO_FILE_plus->_shortbuf`.
2. overwrite `_malloc_hook`(_malloc_hook is between stdin buf and main_arena)
3. malloc()
* [2017 HITCON ghost in heap](https://github.com/scwuaptx/CTF/tree/master/2017-writeup/hitcon/ghost_in_the_heap)
