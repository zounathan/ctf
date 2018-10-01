	.file	"scheduled_setitimer.c"

	.text
.globl setitimer_hdr
	.type	setitimer_hdr, @function

setitimer_hdr:
	pusha
	# sys_setitimer(ITIMER_REAL, *struct_itimerval, NULL)
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	xorl	%edx, %edx
	mov	$104, %al
	jmp	struct_itimerval
load_struct:
	pop	%ecx
	int	$0x80
	popa
	jmp	handler

struct_itimerval:
	call	load_struct
	.long	0x0	# seconds
	.long	0x5000	# microseconds
	.long	0x0	# seconds
	.long	0x5000	# microseconds

handler:
	pusha
	# signal(SIGALRM, handler)
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	mov	$48, %al
	mov	$14, %bl
	jmp	handler_end
load_handler:
	pop	%ecx
	subl	$0x19, %ecx # adjust %ecx to point handler()
	int	$0x80
	popa
	jmp	shellcode

handler_end:
	call load_handler

shellcode:
	pusha
	# write(stdout, string, strlen)
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	xorl	%edx, %edx
	mov	$4, %al 
	mov	$1, %bl
	jmp msg_string
load_msg_string:
	pop	%ecx
	mov	$5, %dl
	int	$0x80
	popa
	ret

msg_string:
	call load_msg_string
	.string	"haha\n"

	.size	setitimer_hdr, .-setitimer_hdr
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
