Stack Overflow
=
# What's the Stack?
> * [Stack](https://en.wikipedia.org/wiki/Stack_(abstract_data_type))<br>
![](https://timgsa.baidu.com/timg?image&quality=80&size=b9999_10000&sec=1523505359799&di=87abd9e8831938abe04836ae15d0c8a8&imgtype=0&src=http%3A%2F%2Fimages0.cnblogs.com%2Fblog2015%2F688670%2F201507%2F271950018913915.png)
# Protection schemes
> * [Nonexecutable stack(NX)](https://en.wikipedia.org/wiki/NX_bit)
> * [Stack Canary](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries)
> * [Randomization](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Randomization)

# Exploiting Stack Overflow
## Exploiting Without Any Protection
> 1. Put shellcode on the memory(stack or any with x permission memory).<br>
> 2. Control EIP to the shellcode memory.<br>
> * [example - 0x01 Control Flow Hijack 程序流劫持](https://www.tuicool.com/articles/ZruA7bZ)
> ### Get shellcode
> * [Pwntools.shellcraft](http://pwntools.readthedocs.io/en/stable/shellcraft.html)
> * [Metasploit](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)

## Exploiting With Nonexecutable Protection
Using ROP(Return-oriented programming)
> * [Ret2libc](https://www.tuicool.com/articles/ZruA7bZ)<br>
> * Stack Pivot<br>
> * GOT hijack<br>
>   * With randomization protection, the GOT can be changed to the code address in that function.<br> 
>   * [0ctf-blackhole](https://kileak.github.io/ctf/2018/0ctf-qual-blackhole/)<br>
>   * Since the last 3 nibbles of an address won’t be randomized by ASLR, we can overwrite the LSB of alarm got with `0x85` to change it into a neat syscall gadget.<br>
```code
alarm:
000b8180   mov eax, 0x25
000b8185   syscall                      # we want to call this
000b8187   cmp rax, 0xfffffffffffff001
000b818d   jae 0xb8190
000b818f   retn
```
> * [DynElf(no libc need)](http://docs.pwntools.com/en/stable/dynelf.html?highlight=DynElf)<br>
> * [mmap/mprotect](https://www.tuicool.com/articles/IfYZri3)<br>
> * [Return to dl_resolve(no leak need)](http://rk700.github.io/2015/08/09/return-to-dl-resolve)<br>
> * [SROP(Sigreturn Oriented Programming)](https://blog.csdn.net/zsj2102/article/details/78561112)<br>
>   * [pwntools.SROP](http://docs.pwntools.com/en/stable/rop/srop.html?highlight=SROP)<br>

> * x64
>   * [x64_ROP](https://www.tuicool.com/articles/ZzI7FrI)<br>
>   * [x64_gadget](https://www.tuicool.com/articles/IfYZri3)

## Exploiting With Stack Canary Protection
> The main methods to bypass the stack canary
> * leak canary
> * control the got of __stack_chk_fail<br>
> [Bypassing Stack Cookies](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)
