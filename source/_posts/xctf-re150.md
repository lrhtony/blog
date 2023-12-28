---
title: 攻防世界-Re150
comments: true
date: 2023-12-28 16:50:27
tags:
  - CTF
categories:
  - 技术
---

学会dump程序
## 分析

用ida打开文件，可以看到只有start函数，里面是一个类似壳一样解密程序的代码

```c
void start()
{
  int v0; // eax
  int v1; // ecx
  int v2; // edi
  int v3; // esi

  v0 = sys_write(1, (char *)start + 14, 9u);
  v1 = *(_DWORD *)((char *)start + 10);
  v2 = *(_DWORD *)((char *)start + 6);
  v3 = 0;
  do
  {
    *(_BYTE *)(v2 + v3) = ((unsigned __int8)(*(_BYTE *)(v2 + v3) ^ 0x42) >> 3) | (32 * (*(_BYTE *)(v2 + v3) ^ 0x42));
    ++v3;
    --v1;
  }
  while ( v1 );
  __asm { retn }
}
```

于是乎我们可以在循环后打一个断点，逐步调试，观察情况![ida-debugger](https://img.jks.moe/od/01tklsjzhf2odlypq6xvejclvdyymiojvn)

可以发现代码已经解密

这里我们将解密后的整个程序dump出来。可以用ida的script：

```c
auto i,fp;
fp = fopen("d:\\dump.dex","wb");
for (i = start_address; i <= end_address; i++)
     fputc(Byte(i),fp);
```

```python
import idaapi
data = idaapi.dbg_read_memory(start_address, data_length)
fp = open('d:\\dump', 'wb')
fp.write(data)
fp.close()
```

或者是gdb调试到解密后运行`dump memory dump_filename start_address end_address`

将dump出来的程序去除花指令后整理可得到以下函数

```c
void __fastcall sub_8048425(int a1)
{
  char input_str[14]; // [esp+1h] [ebp-39h] BYREF
  int v2; // [esp+1Eh] [ebp-1Ch]
  int v3; // [esp+2Eh] [ebp-Ch]

  v3 = a1;
  *(_DWORD *)input_str = 0;
  v2 = 0;
  memset(&input_str[1], 0, 4 * (((input_str - &input_str[1] + 33) & 0xFFFFFFFC) >> 2));
  __isoc99_scanf("%32s", input_str);
  sub_804848F(input_str, encode);
}
```

```c
void __cdecl sub_804848F(char input_str[], char encode[])
{
  int i; // [esp+Ch] [ebp-1Ch]

  for ( i = 0; input_str[i]; ++i )
    input_str[i] = ((input_str[i] << (8 - i % 8)) | ((int)(unsigned __int8)input_str[i] >> (i % 8))) ^ i;
  sub_8048583(input_str, encode);
}
```

```c
int __cdecl sub_8048583(char input_str[], char encode[])
{
  unsigned int i; // eax
  char addr[44]; // [esp+Ch] [ebp-38h] BYREF
  int v5; // [esp+38h] [ebp-Ch]
  int j; // [esp+3Ch] [ebp-8h]

  for ( i = 0; i < 0x20; i += 4 )
    *(_DWORD *)&addr[i + 12] = 0;
  j = 0;
  v5 = 0;
  qmemcpy(addr, "right\nerror\n", 12);
  while ( encode[j] )
  {
    addr[j + 12] = encode[j] ^ 0x20;
    ++j;
  }
  for ( j = 0; input_str[j] == addr[j + 12] && input_str[j] && addr[j + 12]; ++j )
    ;
  if ( input_str[j] || addr[j + 12] )
    return sys_write(1, &addr[6], 6u);          // error
  else
    return sys_write(1, addr, 6u);              // right
}
```

## 结果

写出对应解密脚本

```python
encode = [0x73, 0x8D, 0xF2, 0x4C, 0xC7, 0xD4, 0x7B, 0xF7, 0x18, 0x32, 0x71, 0x0D, 0xCF, 0xDC, 0x67, 0x4F, 0x7F, 0x0B, 0x6D]

for i in range(len(encode)):
    encode[i] ^= 0x20
    encode[i] ^= i
    encode[i] = (encode[i] >> (8 - i % 8)) & 0xff | (encode[i] << (i % 8)) & 0xff

for c in encode:
    print(chr(c), end='')
# SYC{>>Wh06m1>>R0Ot}
```

