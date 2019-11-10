SandBox
=
# Seccomp(secure computing)
* 一般用作在linux下实现沙箱。chrome,firefox在linux下的沙箱就是seccomp做的
* 可以限制用户可以使用的syscall,白名单黑名单皆可。遇上不同的syscall时要采取什么措施(kill,allow,trap等)
* 稍微复杂的操作:可以利用filter来进行简单的计算以及条件判断;
* 出现不谨慎或者误用的情况还是可以绕过这些限制

## Enable seccomp
### libseccomp
[libseccomp](https://github.com/seccomp/libseccomp)对bpf做了封装，省去使用者学习bpf语法的过程
* seccomp_init
* seccomp_rule_add
* seccomp_load
```c
scmp_filter_ctx ctx = NULL;
ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
seccomp_load(ctx);
```
### prctl
1. 设置`PR_SET_NO_NEW_PROVS`为1，否则execve之后的进程将脱离这个bpf的限制。</br>
`prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`
2. 设置seccomp类型，如`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`，第三个参数为bpf内容，可从内存直接dump。</br>
prctl的两种模式
* SECCOMP_MODE_STRICT</br>
严格模式,只允许read/write/exit
* SECCOMP_MODE_FILTER</br>
Filter模式，设置黑白名单，需自己编写bpf(Berkeley Packet Filter)规则

## Berkeley Packet Filter
### BPF_STMT
写具体的filter指令——BPF_STMT`BPF_STMT(code, k)`</br>
头文件`/usr/include/linux/bpf_common.h`</br>
* Code类型
1. BPF_LD	将值复制到累加器（A）
* Load width: BPF_W, BPF_H,BPF_B
* Address ref: BPF_ABS,
* load常数进register: BPF_IMM
* 查看data这个结构`Linux/include/uapi/linux/seccomp.h`,取数据以这个结构开头为基地址,可以取nr/arch/pc/args
```c
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};
```
* nr: syscall number
* arch: 定义在audit.h
	* i386: 0x40000003
	* x86-64: 0xc000003e
* instruction_pointer:syscall 那行指令的地址
* args:syscall 参数(最多六个参数的数组)
	* i386: ebx, ecx, edx, esi, edi
	* x86-64: rdi, rsi, rdx, r10, r8, r9
```c
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, k)   A <- P[k:4]     // 将k字节偏移处往后4个字节存入A中
BPF_STMT(BPF_LD | BPF_H | BPF_ABS, k)   A <- P[k:2]     // 将k字节偏移处往后2个字节存入A中
BPF_STMT(BPF_LD | BPF_B | BPF_ABS, k)   A <- P[k:1]     // 将k字节偏移处往后1个字节存入A中
BPF_STMT(BPF_LD | BPF_W | BPF_IND, k)   A <- P[X+k:4]   // 将(X寄存器值与k的和)偏移处往后4个字节存入A中
BPF_STMT(BPF_LD | BPF_H | BPF_IND, k)   A <- P[X+k:2]   // 将(X寄存器值与k的和)偏移处往后2个字节存入A中
BPF_STMT(BPF_LD | BPF_B | BPF_IND, k)   A <- P[X+k:1]   // 将(X寄存器值与k的和)偏移处往后1个字节存入A中
BPF_STMT(BPF_LD | BPF_W | BPF_LEN)      A <- len        // 将包长度存存入A中
BPF_STMT(BPF_LD | BPF_IMM, k)           A <- k          // 将k值存入A中
BPF_STMT(BPF_LD | BPF_MEM, k)           A <- M[k]       // 将k地址内存的值存入A中
```
2. BPF_LDX	将值复制到寄存器（X）
```c
BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, k)  X <- k              // 将k值存入X中
BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, k)  X <- M[k]           // 将k地址内存的值存入X中
BPF_STMT(BPF_LDX | BPF_W | BPF_LEN, k)  X <- len            // 将包长度存入X中
BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, k)  X <- 4*(P[k:1]&0xf) // 用于计算ip头的长度，将偏移k处一个字节后4位转换成十进制乘以4
```
3. BPF_ST	将A累加器中的值存入存储器中
```c
BPF_STMT(BPF_ST, k)                     M[k] <- X       // 将A中的值存入存储器中
```
4. BPF_STX	将X寄存器中的值存入存储器中
```c
BPF_STMT(BPF_ST, k)                     M[k] <- X       // 将X中的值存入存储器中
```
5. BPF_ALU	将A累加器中的值进行不同方式的计算并存入A中
```c
BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, k)  A <- A + k      // A + k 后存入A中
BPF_STMT(BPF_ALU | BPF_SUB | BPF_K, k)  A <- A - k      // ..
BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, k)  A <- A * k      
BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, k)  A <- A / k
BPF_STMT(BPF_ALU | BPF_AND | BPF_K, k)  A <- A & k
BPF_STMT(BPF_ALU | BPF_OR | BPF_K, k)   A <- A | k
BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, k)  A <- A << k
BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, k)  A <- A >> k
BPF_STMT(BPF_ALU | BPF_ADD | BPF_X)     A <- A + X
BPF_STMT(BPF_ALU | BPF_SUB | BPF_X)     A <- A - X
BPF_STMT(BPF_ALU | BPF_MUL | BPF_X)     A <- A * X
BPF_STMT(BPF_ALU | BPF_DIV | BPF_X)     A <- A / X
BPF_STMT(BPF_ALU | BPF_AND | BPF_X)     A <- A & X
BPF_STMT(BPF_ALU | BPF_OR | BPF_X)      A <- A | X
BPF_STMT(BPF_ALU | BPF_LSH | BPF_X)     A <- A << X
BPF_STMT(BPF_ALU | BPF_RSH | BPF_X)     A <- A >> X
BPF_STMT(BPF_ALU | BPF_NEG)             A <- -A
```
6. BPF_JMP	条件跳转，根据条件跳转到不同偏移的命令
```c
BPF_JUMP(BPF_JMP | BPF_JA, k)           pc += k         // 永远跳转到这条命令后偏移k的命令  
BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, k)  pc += (A > k) ? jt : jf  // 如果A>k，则跳转到偏移jt的命令，否则跳转到偏移为jf的命令
BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, k)  pc += (A >= k) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, k)  pc += (A == k) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, k) pc += (A & k) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JGT | BPF_X)     pc += (A > X) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X)     pc += (A >= X) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_X)     pc += (A == X) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JSET | BPF_X)    pc += (A & X) ? jt : jf
```
7.BPF_RET	结束指令
8. BPF_MISC	将A中的值存入X中，或将X中的值存入A中
```c
BPF_STMT(BPF_MISC | BPF_TAX)                X <- A      // 将A中的值存入X中
BPF_STMT(BPF_MISC | BPF_TXA)                A <- X      // 将X中的值存入A中
```

### 返回时采取的操作
`Linux/include/uapi/linux/seccomp.h`
* KILL、TRAP、ERRNO、TRACE、ALLOW
```c
#define SECCOMP_RET_KILL_PROCESS 0x80000000U /* kill the process */
#define SECCOMP_RET_KILL_THREAD	 0x00000000U /* kill the thread */
#define SECCOMP_RET_KILL	 SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_TRAP	 0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO	 0x00050000U /* returns an errno */
#define SECCOMP_RET_TRACE	 0x7ff00000U /* pass to a tracer or disallow */
#define SECCOMP_RET_LOG		 0x7ffc0000U /* allow after logging */
#define SECCOMP_RET_ALLOW	 0x7fff0000U /* allow */

/* Masks for the return value sections. */
#define SECCOMP_RET_ACTION_FULL	0xffff0000U
#define SECCOMP_RET_ACTION	0x7fff0000U
#define SECCOMP_RET_DATA	0x0000ffffU
```

### 对bpf程序反编译的方法
* libseccomp有自带的反编译工具，[scmp_bpf_disasm](https://github.com/seccomp/libseccomp/blob/master/tools/scmp_bpf_disasm.c)
`./scmp_bpf_disasm < dump`，可以对照头文件来进行阅读
* 使用[seccomp-tools](https://rubygems.org/gems/seccomp-tools)
```
$ seccomp-tools dump ./pwn
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x04 0x00 0x40000000  if (A >= 0x40000000) goto 0008
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x06 0x00 0x00 0x00000000  return KILL
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 ```

### bpf生成
* [Kafel](https://github.com/google/kafel) is a language and library for specifying syscall filtering policies. The policies
are compiled into BPF code that can be used with seccomp-filter.
* [seccomp_export_bpf](http://homura.cc/blog/archives/145)导出规则

## 绕过seccomp
### retf切换架构
* retf在返回时，除了ret时会pop的寄存器，还会pop掉CS这个寄存器，cs寄存器标识着当前arch到底是64bit还是32bit
	* 32bit——0x23 
	* 64bit——0x32
* i386和x86-64下的syscall编号不一样，execve在i386下是11,x86-64下是59
* 写shellcode的要点
	1. 首先在转换arch前把栈迁移走,例如shellcode自己开个.bss段
	2. 转换架构
	3. 使用转换完之后的架构的汇编写
* [Tokyo Westerns MMA 2016 - Diary](https://ctftime.org/task/2756)

### x32模式
* x32模式是在x86-64下的一种特殊模式,使用64位寄存器+32位地址
* x32模式中nr会加__x32_SYSCALL_BIT (0x40000000)，`/usr/include/asm/unistd_x32.h`，即原本的syscall number +0x40000000,是完全一样的作用

### 特殊syscall
* 几个奇怪的系统调用号，虽然是给x32用的,但是x86-64下一样用，比如`520号`也是系统调用

# ptrace
## ptrace的功能
* 作为tracer来追踪tracee的执行
* 拦截特定事件(TRAP, SYSCALL)
* 读写tracee的内存，cpu上下文等
* 使用ptrace来实现的为人所熟知的工具:gdb (strace也是)

## trace子进程
* ptrace函数
```c
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```
* request的取值
```c
PTRACE_TRACEME		//本进程被其父进程所跟踪。其父进程应该希望跟踪子进程。
PTRACE_PEEKTEXT		//从内存地址中读取一个字节，内存地址由addr给出。 
PTRACE_PEEKDATA		//从内存地址中读取一个字节，内存地址由addr给出。 
PTRACE_PEEKUSER		//从USER区域中读取一个字节，偏移量为addr。
PTRACE_POKETEXT		//往内存地址中写入一个字节。内存地址由addr给出。 
PTRACE_POKEDATA		//往内存地址中写入一个字节。内存地址由addr给出。
PTRACE_POKEUSER		//往USER区域中写入一个字节。偏移量为addr。
PTRACE_CONT		//继续运行
PTRACE_SYSCALL		//跟踪系统调用
PTRACE_SINGLESTEP	//设置单步执行标志
PTRACE_ATTACH		//跟踪指定pid 进程。
PTRACE_DETACH		//结束跟踪

Intel386特有：
PTRACE_GETREGS		//读取寄存器
PTRACE_GETFPREGS	//读取浮点寄存器
PTRACE_SETREGS		//设置寄存器
PTRACE_SETFPREGS	//设置浮点寄存器
```
* Child中调用`ptrace(PTRACE_TRACEME)`，Parent中使用`waitpid(pid)`等待`SIGTRAP`发生
* Child遇到断点`int 3(机器码0xCC)`会中断，等待Parent。通过改代码段可以实现任意地址断点功能。
* 要trace syscall时,可以用`ptrace(PTRACE_SYSCALL)`，Child在每次系统调用开始和结束时中断。

## 绕过ptrace
### fork脱离tracer
* ptrace默认只trace最初PTRACE_TRACEME的那个进程，利用fork，使得fork出来的进程不会被继续trace
* 只要ptrace没有跟踪好fork,vfork,clone, fork后child都不会被ptrace继续跟踪

* 正确的做法
	* 跟踪好fork或者直接禁止直接fork
	* 设`PTRACE_O_TRACECLONE`选项,有fork类操作时候可以跟到

### 杀父进程脱离tracer
* 通过kill杀掉父进程`kill(getppid(), 9)`
* `ppid`无法取得时,可以尝试`pid-1`，也可以在`/proc/self/stat`中可以拿到pid和ppid
* `kill(-1,9)`可以干掉除了自己以外的进程（可以用来杀马）

* 正确做法？
	* 设`PTRACE_O_EXITKILL`可以让tracer结束时把所有tracee kill掉

# 其他常见可用于实现类似沙箱功能的工具
* 细粒度的指令插桩类工具
	* Intel Pintool
	* DynamoRIO
* AppContainer（Edge浏览器，The Awesome AppJailLaucher）
* Chrome浏览器windows沙箱
* A restricted token
* The Windows job object
* The Windows desktop object
* The integrity levels
* SELinux
	* MAC(mandatory access control)
	* DAC(discretionary access control)

# Reference
https://veritas501.space/2018/05/05/seccomp%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/
