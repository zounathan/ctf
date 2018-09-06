# tw playing card
Searching the string `win`, we can easily find the function `sub_401aa0`.
With some resvering or debugging, we know that function `sub_401160` generates the cards and function `sub_4017B0` checks the result. When the result of function `sub_4017B0` is 1, we think the elf will put the flag. Actually, it doesn't do that.
# sub_4017B0
First we analyse the function `sub_4017B0`. When this function returns 1, it should meet 2 conditions:
1. qword_6152B8 > 0, which means we should win at least once.
2. Your 5 cards should be `spade 2`,`heart 11`, `spade 6`, `heart 4` and `diamod 9`.
we can change the return value of function `sub_410090` in the `sub_401160` to obtain the 5 cards.
Then running the elf, we get the segment fault at address `0x401ecb`. 
# sub_41096
Because the return value of function `sub_41096` is 0, the elf crashes with segment fault. Step into function, we find the `v24>v26` is always true, which leads to return 0.
```c
  v21 = (_QWORD *)sub_410800(&v28, v17);
  v23 = v21;
  if ( v21 )
  {
    v22 = *v21;
    v24 = *((unsigned int *)v21 + *v21 + 3);
    v25 = 4LL * *v21;
    v26 = v25 - 4;
    if ( v24 < v25 - 7 )
      return sub_40BDA0(0LL);
  }
  else
  {
    v24 = MEMORY[0xC];
    v26 = -4LL;
  }
  if ( v26 < v24 )
    return sub_40BDA0(0LL);
 result = sub_40F1B0(v24, v17, v22);
  if ( v24 )
  {
    v27 = 0LL;
    do
    {
      *(_BYTE *)(result + v27 + 16) = *((_DWORD *)v23 + (v27 >> 2) + 4) >> 8 * (v27 & 3);
      ++v27;
    }
    while ( v24 != v27 );
  }
  return result;
```
Looking at the following code, it has no relation ship with the `v22`, `v25`, `v26`.And we find function `sub_410800` is the decryption of `xxtea algorithm`. So we guess that the code above is wrong. We patch the code, and set `v24=v25` to make elf puts deciphering string. But there is something wrong with the string. It has much nonprintable characters.
# sub_402010
Checking the function `sub_41096`'s args, we find the ciphertext is stored in `qword_6152C8`, which is setted in function `sub_402010`. It is converted from `unk_4113A0` with `xor 0x20`.
Recovering the `qword_6152C8` to `unk_4113A0`, we can finally get the correct flag.

1. ciphertxt: `unk_4113A0`
2. key: the 5 cards
3. algorithm: xxtea

TWCTF{D!d_y0u_s33_7he_n!m_b!nary:)}



