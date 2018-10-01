#!/usr/bin/perl

#
# This utility trasform hexdump output:
#
# $ hexdump -C -s 0x0000034 -n 90 scheduled_setitimer.o
# 00000034  60 31 c0 31 db 31 d2 b0  68 eb 05 59 cd 80 eb 15  |`1.1.1..h..Y....|
# 00000044  e8 f6 ff ff ff 00 00 00  00 00 02 00 00 00 00 00  |................|
# 00000054  00 00 02 00 00 31 c0 31  db b0 30 b3 0e eb 08 59  |.....1.1..0....Y|
# 00000064  83 e9 17 cd 80 61 c3 e8  f3 ff ff ff 60 31 c0 31  |.....a......`1.1|
# 00000074  db 31 d2 b0 04 b3 01 eb  07 59 b2 05 cd 80 61 c3  |.1.......Y....a.|
# 00000084  e8 f4 ff ff ff 68 61 68  61 0a                    |.....haha.|
#
# Into a c-style shellcode string:
#
# $ echo $hexdump_output | hexdump_to_cstring.pl
# \x60\x31\xc0\x31\xdb\x31\xd2\xb0\x68\xeb\x05\x59\xcd\x80\xeb\x15\xe8\xf6\xff\xff\xff\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x31\xc0\x31\xdb\xb0\x30\xb3\x0e\xeb\x08\x59\x83\xe9\x17\xcd\x80\x61\xc3\xe8\xf3\xff\xff\xff\x60\x31\xc0\x31\xdb\x31\xd2\xb0\x04\xb3\x01\xeb\x07\x59\xb2\x05\xcd\x80\x61\xc3\xe8\xf4\xff\xff\xff\x68\x61\x68\x61\x0a
#

@input = <STDIN>;

foreach (@input) {
	
	@elems = split(/\s+/);
	
	foreach (@elems) {
		
		if(length($_) == 2 && $_ =~ /[a-f0-9]{2}/) {
			print '\x'.$_;
		}

	}
}

print "\n";

