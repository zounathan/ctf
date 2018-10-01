	.file	"scheduled_alarm.c"

	.text
.globl handler
	.type	handler, @function

handler:
	pusha
	# alarm(timeout)
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	mov	$27, %al
	mov	$0x1, %bl	# 1 second
	int	$0x80

schedule:
	# signal(SIGALRM, handler)
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	mov	$48, %al
	mov	$14, %bl
	jmp	schedule_end
load_handler:
	pop	%ecx
	subl	$0x23, %ecx # adjust %ecx to point handler()
	int	$0x80
	popa
	jmp	shellcode

schedule_end:
	call load_handler

shellcode:
	pusha
	# write(stdout, string, strlen)
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	xorl	%edx, %edx
	mov	$4, %al 
	mov	$1, %bl
	jmp	msg_string
load_msg_string:
	pop	%ecx
	mov	$5, %dl
	int	$0x80
	popa
	ret

msg_string:
	call load_msg_string
	.string	"haha\n"

	.size	handler, .-handler
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
