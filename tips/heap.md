Heap 
=
# memory allocators
> * dlmalloc – General purpose allocator
> * `ptmalloc2 – glibc`
> * jemalloc – FreeBSD and Firefox
> * tcmalloc – Google
> * libumem – Solaris<br>

> `ptmalloc2` was forked from `dlmalloc`. After fork, `threading support` was added to it and got released in 2006. After its official release, ptmalloc2 got integrated into glibc source code.<br>
> [malloc internally invokes either `brk` or `mmap` syscall](https://sploitfun.wordpress.com/2015/02/11/syscalls-used-by-malloc)
![](http://epo.alicdn.com/image/41u4qg499890.png)
![](http://epo.alicdn.com/image/41u4qk4f6q40.png)

# Arena
> After malloc(eventhough user requests small size), heap memory of size 132 KB is created. This contiguous region of heap memory is called `arena`. Since this arena is created by main thread its called `main arena`.<br>
> Further allocation requests keeps using this arena until it runs out of free space. When arena runs out of free space, it can grow by increasing program break location (After growing top chunk’s size is adjusted to include the extra space). Similarly arena can also shrink when there is lot of free space on `top chunk`.<br>
```code
For 32 bit systems:
     Number of arena = 2 * number of cores + 1.
For 64 bit systems:
     Number of arena = 8 * number of cores + 1.
 ```
## Multiple Arena
> * When main thread, calls malloc for the first time already created main arena is used without any contention.
> * When thread 1 and thread 2 calls malloc for the first time, a new arena is created for them and its used without any contention. Until this point threads and arena have one-to-one mapping.
> * When thread 3 calls malloc for the first time, number of arena limit is calculated. Here arena limit is crossed, hence try `reusing` existing arena’s (Main arena or Arena 1 or Arena 2)
>> Reuse:
>>   * Once loop over the available arenas, while looping try to lock that arena.
>>   * If locked successfully (lets say main arena is locked successfully), return that arena to the user.
>>   * If no arena is found free, block for the arena next in line.
> * Now when thread 3 calls malloc (second time), malloc will try to use last accessed arena (main arena). If main arena is free its used else thread3 is blocked until main arena gets freed. Thus now main arena is shared among main thread and thread 3.

## Multiple Heaps
### _heap_info
> * Heap Header – A single thread arena can have multiple heaps. Each heap has its own header. Why multiple heaps needed? To begin with every thread arena contains ONLY one heap, but when this heap segment runs out of space, new heap (non contiguous region) gets mmap’d to this arena.
> * Main arena dont have multiple heaps and hence no heap_info structure. When main arena runs out of space, sbrk’d heap segment is extended (contiguous region) until it bumps into memory mapping segment.
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
> * Main arena and thread arena (single heap segment)
![](http://epo.alicdn.com/image/41u4skqanfb0.png)
> * Thread arena (multiple heap segment’s)
![](http://epo.alicdn.com/image/41u4snuicn70.png)

### malloc_state
> * Arena Header – A single thread arena can have multiple heaps, but for all those heaps only a single arena header exists. Arena header contains information about bins, top chunk, last remainder chunk…
> * Unlike thread arena, main arena’s arena header isnt part of sbrk’d heap segment. Its a global variable and hence its found in libc.so’s data segment.
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
> * Chunk Header – A heap is divided into many chunks based on user requests. Each of those chunks has its own chunk header.
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
> A chunk found inside a heap segment can be one of the below types:
> * Allocated chunk
> * Free chunk
> * Top chunk
> * Last Remainder chunk

## Allocated chunk
```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   pre_size    |   size  |N|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   User data starts here...    .
      .                               .
      . (malloc_usable_size() bytes)  .
      .                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+
      |             Size of chunk     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
> * prev_size<br>
> If the previous chunk is free, this field contains the size of previous chunk. Else if previous chunk is allocated, this field contains previous chunk’s user data.
> * size<br>
> This field contains the size of this allocated chunk. Last 3 bits of this field contains flag information.
>   * PREV_INUSE (P) – This bit is set when previous chunk is allocated.
>   * IS_MMAPPED (M) – This bit is set when chunk is mmap’d.
>   * NON_MAIN_ARENA (N) – This bit is set when this chunk belongs to a thread arena.

## Free chunk
```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   pre_size    |   size  |N|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      fd       |       bk      |
      .-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      .                               .
      .                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+
      |             Size of chunk     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
> * prev_size<br>
> No two free chunks can be adjacent together. When both the chunks are free, its gets combined into one single free chunk. Hence always previous chunk to this freed chunk would be allocated and therefore prev_size contains previous chunk’s user data.
> * size<br>
> This field contains the size of this free chunk.
> * fd<br>
> Forward pointer – Points to next chunk in the same bin (and NOT to the next chunk present in physical memory).
> * bk<br>
> Backward pointer – Points to previous chunk in the same bin (and NOT to the previous chunk present in physical memory).

## Top chunk
> Chunk which is at the top border of an arena is called top chunk. It doesn't belong to any bin. Top chunk is used to service user request when there is NO free blocks, in any of the bins.<br>
> * If top chunk size is greater than user requested size top chunk is split into two:
>   * User chunk (of user requested size)
>   * Remainder chunk (of remaining size), The remainder chunk becomes the new top. <br>
> * If top chunk size is lesser than user requested size, top chunk is put to unsorted bin, and extend new top chunk using sbrk (main arena) or mmap (thread arena) syscall. 

## Last Remainder chunk
> When a user request of small chunk, cannot be served by a small bin and unsorted bin, binmaps are scanned to find next largest (non empty) bin. As said earlier, on finding the next largest (non empty) bin, its split into two, user chunk gets returned to the user and remainder chunk gets added to the unsorted bin. In addition to it, it becomes the new last remainder chunk.

# Bins
> * Fast bin
> * small bin
> * large bin
> * unsorted bin

> Datastructures used to hold these bins are
> * fastbinsY: This array hold fast bins.
> * bins: This array hold unsorted, small and large bins. Totally there are 126 bins([malloc_state](#malloc_state))
>   * Bin 1 – Unsorted bin
>   * Bin 2 to Bin 63 – Small bin
>   * Bin 64 to Bin 126 – Large bin

## Fast bin
> Chunks of size 16 to 80 bytes(x64 32 to 128 bytes) is called a fast chunk. Bins holding fast chunks are called fast bins. Among all the bins, fast bins are faster in memory allocation and deallocation.
> * Number of bins – 10
>   * Each fast bin contains a single linked list (a.k.a binlist) of free chunks. Single linked list is used since in fast bins chunks are not removed from the middle of the list. Both addition and deletion happens at the front end of the list – LIFO.
> * Chunk size – 8 bytes apart
>   * Fast bins contain a binlist of chunks whose sizes are 8 bytes apart. ie) First fast bin (index 0) contains binlist of chunks of size 16 bytes, second fast bin (index 1) contains binlist of chunks of size  24 bytes and so on…
>   * Chunks inside a particular fast bin are of same sizes.
> * During malloc initialization, maximum fast bin size is set to 64 (!80) bytes. Hence by default chunks of size 16 to 64 is categorized as fast chunks.
> * No Coalescing – Two chunks which are free can be adjacent to each other, it doesnt get combined into single free chunk. No coalescing could result in external fragmentation but it speeds up free!!
> * malloc(fast chunk) –
>   * Initially fast bin max size and fast bin indices would be empty and hence eventhough user requested a fast chunk, instead of fast bin code, small bin code tries to service it.
>   * Later when its not empty, fast bin index is calculated to retrieve its corresponding binlist.
>   * First chunk from the above retrieved binlist is removed and returned to the user.
> * free(fast chunk) –
>   * Fast bin index is calculated to retrieve its corresponding binlist.
>   * This free chunk gets added at the front position of the above retrieved binlist.
![](http://epo.alicdn.com/image/420rc04q9ad0.png)

## small bin

## large bin

## unsorted bin

# Malloc

# Realloc

# Free

# Reference
> * http://www.freebuf.com/articles/system/151372.html
> * https://paper.seebug.org/255/#0-tsina-1-29759-397232819ff9a47a7b7e80a40613cfe1
> * https://www.cnblogs.com/alisecurity/p/5486458.html
> * https://www.cnblogs.com/alisecurity/p/5520847.html

https://paper.seebug.org/521/
https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
https://blog.csdn.net/qq_35519254/article/details/78627056
