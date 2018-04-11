Stack Overflow
=
# What's the Stack?
> * [Stack](https://en.wikipedia.org/wiki/Stack_(abstract_data_type))

# Protection schemes
> * [Nonexecutable stack(NX)](https://en.wikipedia.org/wiki/NX_bit)
> * [Stack Canary](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries)
> * [Randomization](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Randomization)

# Exploiting Stack Overflow
## Exploiting Without Any Protection
> 1, Put shellcode on the memory(stack or any with x permission memory).<br>
> 2, Control EIP to the shellcode memory.<br>
> * [example - 0x01 Control Flow Hijack 程序流劫持](https://www.tuicool.com/articles/ZruA7bZ)
> ### Get shellcode
>> * [Pwntools.shellcraft](http://pwntools.readthedocs.io/en/stable/shellcraft.html)
>> * [Metasploit](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)

## Exploiting With Nonexecutable Protection
> ### ROP(Return-oriented programming)
>> 1, [Ret2libc](https://www.tuicool.com/articles/ZruA7bZ)<br>
>> 2, Stack Pivot<br>
>> 3, GOT hijack<br>
>>> With randomization protection, the GOT can be changed to the code address in that function.<br> 
>>> [0ctf-blackhole](https://kileak.github.io/ctf/2018/0ctf-qual-blackhole/)<br>
>>> Since the last 3 nibbles of an address won’t be randomized by ASLR, we can overwrite the LSB of alarm got with `0x85` to change it into a neat syscall gadget.<br>
```code
alarm:
000b8180   mov eax, 0x25
000b8185   syscall                      # we want to call this
000b8187   cmp rax, 0xfffffffffffff001
000b818d   jae 0xb8190
000b818f   retn
```
>> 4, [DynElf(no libc need)](http://docs.pwntools.com/en/stable/dynelf.html?highlight=DynElf)<br>
>> 5, [mmap/mprotect](https://www.tuicool.com/articles/IfYZri3)<br>
>> 6, [Return to dl_resolve(no leak)](http://rk700.github.io/2015/08/09/return-to-dl-resolve)<br>
>> 7, [SROP(Sigreturn Oriented Programming)](https://blog.csdn.net/zsj2102/article/details/78561112)<br>
>>> * [pwntools.SROP](http://docs.pwntools.com/en/stable/rop/srop.html?highlight=SROP)<br>

>> x64
>>> 1, [x64_ROP](https://www.tuicool.com/articles/ZzI7FrI)<br>
>>> 2, [x64_gadget](https://www.tuicool.com/articles/IfYZri3)
