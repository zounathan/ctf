	.text
.globl main
	.type	main, @function
main:
    push    $0xbeef
    movd    (%esp), %mm0

    push    $0xdead0000
    movd    (%esp), %mm1

    paddd   %mm1, %mm0

    xorl    %eax, %eax
    xorl    %ebx, %ebx

    movd    %mm0, (%esp)
    pop     %ebx

sys_exit_call:
    xorl    %eax, %eax
    mov     $1, %al
    int     $0x80
