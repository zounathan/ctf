#!/usr/bin/perl

if (!$ARGV[0]) {
    print "Syscall shellcode generator\n";
    print "Usage:\n\t$0 syscall\n";
    print "Example:\n\t$0 sys_open\n";
    exit(1);
}

$name = $ARGV[0];

$syscall = `cat syscalls.txt | egrep " $name( .+|\$)"`;
chomp($syscall);

@parts = split(/\s+/, $syscall);
if (scalar(@parts) < 2) {
    print "syscall not found.\n";
    exit 1;
}

# Header
print $name."_call:\n";
print "\t# call to $name(";
print $parts[2] if $parts[2];
print ", ".$parts[3] if $parts[3];
print ", ".$parts[4] if $parts[4];
print ")\n";

# EAX
print "\txorl\t\%eax, \%eax\n";
print "\tmov\t\$".$parts[0].", %al\n";

# EBX
if ($parts[2]) {
    print "\txorl\t\%ebx, \%ebx\n";
    print "\tmov\t".$parts[2].", %bl\n";
}

# ECX
if ($parts[3]) {
    print "\txorl\t\%ecx, \%ecx\n";
    print "\tmov\t".$parts[3].", %cl\n";
}

# EDX
if ($parts[4]) {
    print "\txorl\t\%edx, \%edx\n";
    print "\tmov\t".$parts[4].", %dl\n";
}

# INT
print "\tint\t\$0x80\n";


