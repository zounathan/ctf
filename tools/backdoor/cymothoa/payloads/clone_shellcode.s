	.text
.globl main
	.type	main, @function
main:
    pusha           # save registers (needed by parent process)

    # call to sys_clone

    xorl    %eax, %eax
    mov     $120, %al

    movl     $0x18900, %ebx  # flags: (CLONE_VM|CLONE_SIGHAND|CLONE_THREAD|CLONE_PARENT)

    int     $0x80

    test %eax, %eax
    jz shellcode    # child jumps to shellcode

    popa            # parent process
    ret

    shellcode:      # append your shellcode
