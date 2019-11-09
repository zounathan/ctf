Heap 
=
# memory allocators
* dlmalloc – General purpose allocator
* `ptmalloc2 – glibc`
* jemalloc – FreeBSD and Firefox
* tcmalloc – Google
* libumem – Solaris<br>

`ptmalloc2` was forked from `dlmalloc`. After fork, `threading support` was added to it and got released in 2006. After its official release, ptmalloc2 got integrated into glibc source code.<br>
[malloc internally invokes either `brk` or `mmap` syscall](https://sploitfun.wordpress.com/2015/02/11/syscalls-used-by-malloc)
![](http://epo.alicdn.com/image/41u4qg499890.png)
![](http://epo.alicdn.com/image/41u4qk4f6q40.png)

# Arena
After malloc(eventhough user requests small size), heap memory of size 132 KB is created. This contiguous region of heap memory is called `arena`. Since this arena is created by main thread its called `main arena`.<br>
Further allocation requests keeps using this arena until it runs out of free space. When arena runs out of free space, it can grow by increasing program break location (After growing top chunk’s size is adjusted to include the extra space). Similarly arena can also shrink when there is lot of free space on `top chunk`.<br>
```code
For 32 bit systems:
     Number of arena = 2 * number of cores + 1.
For 64 bit systems:
     Number of arena = 8 * number of cores + 1.
 ```
## Multiple Arena
* When main thread, calls malloc for the first time already created main arena is used without any contention.
* When thread 1 and thread 2 calls malloc for the first time, a new arena is created for them and its used without any contention. Until this point threads and arena have one-to-one mapping.
* When thread 3 calls malloc for the first time, number of arena limit is calculated. Here arena limit is crossed, hence try `reusing` existing arena’s (Main arena or Arena 1 or Arena 2)
>Reuse:
>  * Once loop over the available arenas, while looping try to lock that arena.
>  * If locked successfully (lets say main arena is locked successfully), return that arena to the user.
>  * If no arena is found free, block for the arena next in line.
* Now when thread 3 calls malloc (second time), malloc will try to use last accessed arena (main arena). If main arena is free its used else thread3 is blocked until main arena gets freed. Thus now main arena is shared among main thread and thread 3.

## Multiple Heaps
### _heap_info
* Heap Header – A single thread arena can have multiple heaps. Each heap has its own header. Why multiple heaps needed? To begin with every thread arena contains ONLY one heap, but when this heap segment runs out of space, new heap (non contiguous region) gets mmap’d to this arena.
* Main arena dont have multiple heaps and hence no heap_info structure. When main arena runs out of space, sbrk’d heap segment is extended (contiguous region) until it bumps into memory mapping segment.
```c
typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```
* Main arena and thread arena (single heap segment)
![](http://epo.alicdn.com/image/41u4skqanfb0.png)
* Thread arena (multiple heap segment’s)
![](http://epo.alicdn.com/image/41u4snuicn70.png)

### malloc_state
* Arena Header – A single thread arena can have multiple heaps, but for all those heaps only a single arena header exists. Arena header contains information about bins, top chunk, last remainder chunk…
* Unlike thread arena, main arena’s arena header isnt part of sbrk’d heap segment. Its a global variable and hence its found in libc.so’s data segment.
```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  /* The first is Unsorted bin */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  */
  struct malloc_state *next_free;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

### malloc_chunk
* Chunk Header – A heap is divided into many chunks based on user requests. Each of those chunks has its own chunk header.
```c
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

# Chunk
A chunk found inside a heap segment can be one of the below types:
* Allocated chunk
* Free chunk
* Top chunk
* Last Remainder chunk

## Allocated chunk
```
  chunk-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   pre_size    |   size  |N|M|P|
      mem-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   User data starts here...    .
      .                               .
      . (malloc_usable_size() bytes)  .
      .                               |
  nextchunk-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   pre_size    |   size  |N|M|P|
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
* prev_size<br>
If the previous chunk is free, this field contains the size of previous chunk. Else if previous chunk is allocated, this field contains previous chunk’s user data.
* size<br>
This field contains the size of this allocated chunk. Last 3 bits of this field contains flag information.
  * PREV_INUSE (P) – This bit is set when previous chunk is allocated.
  * IS_MMAPPED (M) – This bit is set when chunk is mmap’d.
  * NON_MAIN_ARENA (N) – This bit is set when this chunk belongs to a thread arena.

## Free chunk
```
  chunk-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   pre_size    |   size  |N|M|P|
      mem-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      fd       |       bk      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  fd_nextsize  |  bk_nextsize  |
      .-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      .                               .
      .                               |
  nextchunk-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   pre_size    |   size  |N|M|P|
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
* prev_size<br>
No two free chunks can be adjacent together. When both the chunks are free, its gets combined into one single free chunk. Hence always previous chunk to this freed chunk would be allocated and therefore prev_size contains previous chunk’s user data.
* size<br>
This field contains the size of this free chunk.
* fd<br>
Forward pointer – Points to next chunk in the same bin (and NOT to the next chunk present in physical memory).
* bk<br>
Backward pointer – Points to previous chunk in the same bin (and NOT to the previous chunk present in physical memory).

## Top chunk
Chunk which is at the top border of an arena is called top chunk. It doesn't belong to any bin. Top chunk is used to service user request when there is NO free blocks, in any of the bins.<br>
* Top chunk's size has to be page aligned
* Top chunk's prev_inuse bit has to be set.
* If top chunk size is greater than user requested size top chunk is split into two:
  * User chunk (of user requested size)
  * Remainder chunk (of remaining size), The remainder chunk becomes the new top. <br>
* If top chunk size is lesser than user requested size, top chunk is put to unsorted bin, and extend new top chunk using sbrk (main arena) or mmap (thread arena) syscall. 

## Last Remainder chunk
When a user request of small chunk, cannot be served by a small bin and unsorted bin, binmaps are scanned to find next largest (non empty) bin. As said earlier, on finding the next largest (non empty) bin, its split into two, user chunk gets returned to the user and remainder chunk gets added to the unsorted bin. In addition to it, it becomes the new last remainder chunk.

# Bins
* Fast bin
* small bin
* large bin
* unsorted bin

Datastructures used to hold these bins are
* fastbinsY: This array hold fast bins.
* bins: This array hold unsorted, small and large bins. Totally there are 126 bins([malloc_state](#malloc_state))
  * Bin 1 – Unsorted bin
  * Bin 2 to Bin 63 – Small bin
  * Bin 64 to Bin 126 – Large bin

## Fast bin
Chunks of size `16 to 64 bytes(x64 32 to 128 bytes)` is called a fast chunk. Bins holding fast chunks are called fast bins. Among all the bins, fast bins are faster in memory allocation and deallocation.
* 10 fast bins in total
* Single linked list. Both addition and deletion happens at the front end of the list – LIFO.
* Chunk size – 8 bytes apart(x64 16 bytes)
* `No Coalescing` – Two chunks which are free can be adjacent to each other, it doesnt get combined into single free chunk. No coalescing could result in external fragmentation but it speeds up free!!
* Will not clear PREV_INUSE when fast chunk is freed.
* malloc(fast chunk) –
  * Initially fast bin max size and fast bin indices would be empty and hence eventhough user requested a fast chunk, instead of fast bin code, small bin code tries to service it.
  * Later when its not empty, fast bin index is calculated to retrieve its corresponding binlist.
  * First chunk from the above retrieved binlist is removed and returned to the user.
* free(fast chunk) –
  * Fast bin index is calculated to retrieve its corresponding binlist.
  * This free chunk gets added at the front position of the above retrieved binlist.
![](http://epo.alicdn.com/image/420rc04q9ad0.png)

## small bin
Chunks of size `less than 512 bytes` is called as small chunk. Bins holding small chunks are called small bins. Small bins are faster than large bins (but slower than fast bins) in memory allocation and deallocation.
* Circular double linked list
* 62 small bins in total
* Chunk size – 8 bytes apart(x64 16 bytes), chunk sizes are the same in each bin
* First In First Out
* `Coalescing` – Two chunks which are free cant be adjacent to each other, it gets combined into single free chunk. 
* malloc(small chunk) –
  * Initially all small bins would be NULL and hence eventhough user requested a small chunk, instead of small bin code, unsorted bin code tries to service it.
  * Also during the first call to malloc, small bin and large bin datastructures (bins) found in malloc_state is initialized ie) bins would point to itself signifying they are empty.
  * Later when small bin is non empty, last chunk from its corresponding binlist is removed and returned to the user.
* free(small chunk) –
  * While freeing this chunk, check if its previous or next chunk is free, if so coalesce ie) unlink those chunks from their respective linked lists and then add the new consolidated chunk into the beginning of unsorted bin’s linked list.

## large bin
Chunks of size `greater than equal to 512` is called a large chunk. Bins holding large chunks are called large bins. Large bins are slower than small bins in memory allocation and deallocation.
* Circular double linked list
* First In First Out
* Except for the fd/bk, there are fd_nextsize/bk_nextsize ptrs. It's also a circular double linked list. 
     1. The chunks are sorted by size. And the biggest ont is at top.
     2. The chunks with the same size are linked by the fd/bk. Except for the top one, the fd_nextsize/bk_nextsize are setted to be 0.
     3. The chunks with different size are lined by fd_nextsize/bk_nextsize. Only the top one of every size chunk is linked.
     ```
	  <---------------------------------------------------------------------<
	  | fd_nextsize                                                         |
	  | >-------------------------------> >-------------------------------> |
	  | | fd_nextsize                   | | fd_nextsize                   | |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
     |      A        |      B      | |      C        |      D      | |      E        |      F      | 
     |    fd->       |    fd->     | |    fd->       |    fd->     | |    fd->       |    fd->     | 
     |    bk<-       |    bk<-     | |    bk<-       |    bk<-     | |    bk<-       |    bk<-     | 
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
          | | bk_nextsize                   | |bk_nextsize                    | |
          | <-------------------------------< <-------------------------------< |
          | bk_nextsize                                                         |
          >--------------------------------------------------------------------->
     ```
* 63 large bins in total
  * Out of these 63 bins:
    * 32 bins contain binlist of chunks of size which are 64 bytes apart. ie) First large bin (Bin 65) contains binlist of chunks of size 512 bytes to 568 bytes, second large bin (Bin 66) contains binlist of chunks of size 576 bytes to 632 bytes and so on…
    * 16 bins contain binlist of chunks of size which are 512 bytes apart.
    * 8 bins contain binlist of chunks of size which are 4096 bytes apart.
    * 4 bins contain binlist of chunks of size which are 32768 bytes apart.
    * 2 bins contain binlist of chunks of size which are 262144 bytes apart.
    * 1 bin contains a chunk of remaining size.
  * Unlike small bin, `chunks inside a large bin are NOT of same size`. Hence they are stored in decreasing order. Largest chunk is stored in the front end while the smallest chunk is stored in the rear end of its binlist.
* `Coalescing` – Two chunks which are free cant be adjacent to each other, it gets combined into single free chunk.
* malloc(large chunk) –
  * Initially all large bins would be NULL and hence eventhough user requested a large chunk, instead of large bin code, next largest bin code tries to service it.
  * Also during the first call to malloc, small bin and large bin datastructures (bins) found in malloc_state is initialized ie) bins would `point to itself` signifying they are empty.
  ```c
  victim->fd_nextsize = victim->bk_nextsize = victim;
  ```
  * Later when large bin is non empty, if the largest chunk size (in its binlist) is greater than user requested size, binlist is walked from rear end to front end, to find a suitable chunk whose size is near/equal to user requested size. Once found, that chunk is split into two chunks
    * User chunk (of user requested size) – returned to user.
    * Remainder chunk (of remaining size) – added to unsorted bin.
  * If largest chunk size (in its binlist) is lesser than user requested size, try to service user request by using the next largest (non empty) bin. Next largest bin code scans the binmaps to find the next largest bin which is non empty, if any such bin found, a suitable chunk from that binlist is retrieved, split and returned to the user. If not found, try serving user request using top chunk.
* free(large chunk) – Its procedure is similar to free(small chunk).<br>

## unsorted bin
When small or large chunk gets freed instead of adding them in to their respective bins, its gets added into unsorted bin.<br>
In the next memory allocation, it will search the unsorted bin first. If the Unsorted bin doesn't have suitable size, the chunks in Unsorted bin will be put to the corresponding Bins(small or large bins).
* Circular double linked list
* `1 bin` in total
* chunk size 64 bytes<br>
![](http://epo.alicdn.com/image/420rc31ppb10.jpg)

# Malloc
1. Search for fast chunks in fast bins
2. Search for chunk of exact size in small bins
3. Loops
   1. Check last_remainder in unsorted bin
       1. if last_remainder is big enough, split it and mark the remaining chunk as the new
last_remainder
   2. Search unsorted bin
       1. return the chunk of exact size, put other chunks into small/large bins
   3. Search small bins and large bins for best-fit chunk(not exact size)
4. Use top chunk

# Realloc
If p=malloc(100)
1. realloc(p,0)=free(p)
2. realloc(p,100), return p, do nothing
3. realloc(p,200)
    1. If next chunk is free, and the size is bigger than (200-100), coalesce p with next chunk and return p.
    2. If next chunk is allocated, or the size is smaller than (200-100), free p and p=malloc(200)
4. realooc(p,40)
    1. The chunk is split into two, 40 and 60
    2. free the chunk(size 60), and put into unsorted bin
    3. return p with size 40
  
# Free
1. Security Check
2. If fast chunk, put into fastbin
3. If previous chunk is free
   1. unlink previous chunk, Coalescing
   2. put merged chunk into unsorted bin
4. If next chunk is top chunk, merge current chunk to the top; And search the fastbinY, do Coalescing, then put merged chunk into unsorted bin.
5. If next chunk is free
   1. unlink next chunk, Coalescing
   2. put merged chunk into unsorted bin
* Unlink
```c
#define unlink( P, BK, FD ) {
BK = P->bk;
FD = P->fd;
FD->bk = BK;
BK->fd = FD;
}
```
* Unlink checks
```c
assert(P->fd->bk == P) assert(P->bk->fd == P)
```
* Bypass unlink checks
  * Find a pointer X to P(*X = P)
  * Fake P->fd = X - 0x18
  * Fake P->bk = X - 0x10
  * Trigger Unlink(P), We have *X = X - 0x18

# Malloc_Consolidate
1. malloc large bin
2. Free the small bin, if the next chunk is the top chunk.

# Tcache
After the glibc-2.26, Tcache(Thread Local Caching) is introduced.
* If the chunk size if less than `0x410`, it will be put in tcache list when it's freeed.
* Tcache has 64 single linked lists for different size chunks. Every list can have 7 chunks at most. 
```c
# define TCACHE_MAX_BINS		64
/* We overlay this structure on the user-data portion of a chunk when the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the per-thread cache (hence "tcache_perthread_struct").  Keeping overall size low is mildly important.  Note that COUNTS and ENTRIES are redundant (we could have just counted the linked list each time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```
Tcache(tcache_perthread_struct) is also a chunk in the heap, which size is `size_chunkhead + size_counts + size_entries = 16 + 64 + 64*8 = 592 = 0x250` in amd64.

* The fd of the chunk in tcache list points to the n`ext chunk's fd address`, instead of the presize address.
* Unlike the fastbin, chunk mallocced from tcache don't check the size.
```
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

static void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```
# Reference
* https://blog.csdn.net/zdy0_2004/article/details/51485198
* https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/comment-page-1/
* https://paper.seebug.org/255/#0-tsina-1-29759-397232819ff9a47a7b7e80a40613cfe1
* http://www.freebuf.com/articles/system/151372.html
* https://github.com/gymgit/glibc-2.23-tmp/blob/master/malloc/malloc.c
