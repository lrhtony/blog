---
title: GeekCTF 2024
comments: true
date: 2024-04-07 00:17:44
tags:
  - CTF
categories:
  - 技术
---
忙着完成学校的任务，随便做一下
## Reverse

### Peer-Trace

题目有`peer`和`puppet`两个文件，`puppet`文件内仅一个异或，过于简单，且将对比的加密结果异或后无有效flag，故转向`peer`文件分析。

通过反汇编得到的代码可以留意到程序内部运行了`puppet`，且通过`ptrace`函数在运行过程中对内存、寄存器进行读取与修改。至于分析过程自然是各种查资料分析，这里先贴一个分析后的代码

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // rax
  __WAIT_STATUS stat_loc; // [rsp+8h] [rbp-188h] BYREF
  int i; // [rsp+10h] [rbp-180h]
  int j; // [rsp+14h] [rbp-17Ch]
  unsigned int pid; // [rsp+18h] [rbp-178h]
  int v9; // [rsp+1Ch] [rbp-174h]
  __int64 __rsi; // [rsp+20h] [rbp-170h]
  unsigned __int64 v12; // [rsp+30h] [rbp-160h]
  __int64 v13; // [rsp+38h] [rbp-158h]
  __int64 v14; // [rsp+40h] [rbp-150h]
  __int64 v15; // [rsp+48h] [rbp-148h]
  __int64 v16; // [rsp+50h] [rbp-140h]
  __int64 v17; // [rsp+58h] [rbp-138h]
  __int64 v18; // [rsp+60h] [rbp-130h]
  __int64 v19; // [rsp+68h] [rbp-128h]
  char v20[32]; // [rsp+70h] [rbp-120h] BYREF
  __int64 _rbp; // [rsp+90h] [rbp-100h]
  unsigned __int64 _rax; // [rsp+C0h] [rbp-D0h]
  __int64 _rsi; // [rsp+D8h] [rbp-B8h]
  __int64 _rdi; // [rsp+E0h] [rbp-B0h]
  __int64 v25[8]; // [rsp+150h] [rbp-40h]

  v25[7] = __readfsqword(0x28u);
  pid = fork();
  if ( !pid )
  {
    ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL);
    execl("puppet", "puppet", 0LL);
  }
  wait((__WAIT_STATUS)&stat_loc);
  if ( ((__int64)stat_loc.__uptr & 0x7F) == 0 )
    return 0;
  ptrace(PTRACE_SYSCALL, pid, 0LL, 0LL);
  HIDWORD(stat_loc.__iptr) = 0;
  __rsi = 0LL;
  while ( 1 )
  {
    wait((__WAIT_STATUS)&stat_loc);
    if ( ((__int64)stat_loc.__uptr & 0x7F) == 0 )
      break;
    if ( !ptrace(PTRACE_PEEKUSER, pid, 0x78LL, 0LL) )// 读取子进程的用户区数据ORIG_RAX
    {
      ptrace(PTRACE_GETREGS, pid, 0LL, v20);    // 获取子进程的寄存器值
      if ( HIDWORD(stat_loc.__iptr) )
      {
        if ( __rsi && _rax )
        {
          v12 = 8 * ((_rax >> 3) + 1);
          for ( i = 0; (__int64)(v12 + 6) >= i; i += 8 )
          {
            v4 = ptrace(PTRACE_PEEKDATA, pid, __rsi + i, 0LL);// 读取子进程的内存数据
            v25[0] = v4;
            v13 = (unsigned __int8)v4;
            LOBYTE(v25[0]) = BYTE5(v4);
            BYTE5(v25[0]) = v4;
            v14 = BYTE1(v4);
            BYTE1(v25[0]) = HIBYTE(v4);
            HIBYTE(v25[0]) = BYTE1(v4);
            v15 = BYTE2(v4);
            BYTE2(v25[0]) = BYTE6(v4);
            BYTE6(v25[0]) = BYTE2(v4);          // 一些顺序调换
            for ( j = 0; i + j < _rax && j <= 7; ++j )
              *((_BYTE *)v25 + j) -= j + i;     // 减一些
            v16 = BYTE3(v25[0]);
            BYTE3(v25[0]) = BYTE4(v25[0]);
            BYTE4(v25[0]) = v16;                // 顺序调换
            ptrace(PTRACE_POKEDATA, pid, i + __rsi, v25[0]);// 修改子进程的内存数据
          }
          __rsi = 0LL;
          break;
        }
        HIDWORD(stat_loc.__iptr) = 0;
      }
      else
      {
        HIDWORD(stat_loc.__iptr) = 1;
        if ( !_rdi )
          __rsi = _rsi;
      }
    }
    ptrace(PTRACE_SYSCALL, pid, 0LL, 0LL);
  }
  ptrace(PTRACE_SINGLESTEP, pid, 0LL, 0LL);     // 设置子进程执行单步指令
  v9 = 0;
  v25[0] = 0xA39C3E6994313F40LL;
  v25[1] = 0x17872470565B9B60LL;
  v25[2] = 0x11A918AABA97CA68LL;
  v25[3] = 0xB8F1B0AB9B3DD3B0LL;
  v25[4] = 0x488749FB6A1835E4LL;
  v25[5] = 0x82926F78FE98158LL;
  while ( 1 )
  {
    wait((__WAIT_STATUS)&stat_loc);
    if ( ((__int64)stat_loc.__uptr & 0x7F) == 0 )
      break;
    v17 = ptrace(PTRACE_PEEKUSER, pid, 0x80LL, 0LL);// 读取子进程的用户区数据RIP
    v18 = ptrace(PTRACE_PEEKDATA, pid, v17, 0LL);// 读取子进程的内存数据
    if ( (v17 & 0xFFF) == 0x292 && (v18 & 0xFFFFFFFFFFLL) == 0xA4458BC289LL )// 程序刚好运行到异或0x28后
    {
      ptrace(PTRACE_GETREGS, pid, 0LL, v20);    // 获取子进程的寄存器值
      v19 = (unsigned int)ptrace(PTRACE_PEEKDATA, pid, _rbp - 0x5C, 0LL);// 读取子进程的内存数据i，异或到第i个byte
      _rax = (unsigned int)_rax + (unsigned __int64)*((unsigned __int8 *)v25 + v19);// 加上v25中的第i个byte
      ptrace(PTRACE_SETREGS, pid, 0LL, v20);    // 设置寄存器值
      v9 = 1;
    }
    ptrace(PTRACE_SINGLESTEP, pid, 0LL, 0LL);   // 设置子进程执行单步指令
  }
  do
  {
    ptrace(PTRACE_CONT, pid, 0LL, 0LL);         // 继续执行子进程
    wait((__WAIT_STATUS)&stat_loc);
  }
  while ( ((__int64)stat_loc.__uptr & 0x7F) != 0 );
  return 0;
}
```

程序对输入整个处理过程大概可以分为两部分，分别是顺序调换和异或后加上数据。

程序首先通过`PTRACE_GETREGS`来获取寄存器的值，根据`cat /usr/include/x86_64-linux-gnu/sys/reg.h`得到

```c
/* Copyright (C) 2001-2023 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _SYS_REG_H
#define _SYS_REG_H      1


#ifdef __x86_64__
/* Index into an array of 8 byte longs returned from ptrace for
   location of the users' stored general purpose registers.  */

# define R15    0
# define R14    1
# define R13    2
# define R12    3
# define RBP    4
# define RBX    5
# define R11    6
# define R10    7
# define R9     8
# define R8     9
# define RAX    10
# define RCX    11
# define RDX    12
# define RSI    13
# define RDI    14
# define ORIG_RAX 15
# define RIP    16
# define CS     17
# define EFLAGS 18
# define RSP    19
# define SS     20
# define FS_BASE 21
# define GS_BASE 22
# define DS     23
# define ES     24
# define FS     25
# define GS     26
#else

/* Index into an array of 4 byte integers returned from ptrace for
 * location of the users' stored general purpose registers. */

# define EBX 0
# define ECX 1
# define EDX 2
# define ESI 3
# define EDI 4
# define EBP 5
# define EAX 6
# define DS 7
# define ES 8
# define FS 9
# define GS 10
# define ORIG_EAX 11
# define EIP 12
# define CS  13
# define EFL 14
# define UESP 15
# define SS   16
#endif

#endif
```

即可得知栈中每个位置实际存储的寄存器，在上面的反编译中已经重命名了。然后通过`PTRACE_PEEKDATA`获取输入，修改，并通过`PTRACE_POKEDATA`存储回puppet。接下来程序通过`PTRACE_PEEKUSER`和`PTRACE_PEEKDATA`，获取当前运行到的地址和当前地址的内容，确保puppet运行到异或0x28后，然后对其值通过`PTRACE_GETREGS`获取，加上v25对应位置的数，再通过`PTRACE_SETREGS`存储回去。最后在puppet中验证。

因此我们可以得到脚本

```python
from ctypes import *

encode = [0xF00F87B5F389569C, 0x3500A2D1A46C9BD1, 0x890A89F330B0D481, 0x200F1FCA08A04513, 0xC3AB5B0381564F00, 0x08953B09BB57FDC7]
key = [0xA39C3E6994313F40, 0x17872470565B9B60, 0x11A918AABA97CA68, 0xB8F1B0AB9B3DD3B0, 0x488749FB6A1835E4, 0x82926F78FE98158]

def LOBYTE(a1):
    return a1 & 0xFF

def BYTE1(a1):
    return (a1 >> 8) & 0xFF

def BYTE2(a1):
    return (a1 >> 16) & 0xFF

def BYTE3(a1):
    return (a1 >> 24) & 0xFF

def BYTE4(a1):
    return (a1 >> 32) & 0xFF

def BYTE5(a1):
    return (a1 >> 40) & 0xFF

def BYTE6(a1):
    return (a1 >> 48) & 0xFF

def HIBYTE(a1):
    return (a1 >> 56) & 0xFF

for i in range(6):
    encode_byte = [LOBYTE(encode[i]), BYTE1(encode[i]), BYTE2(encode[i]), BYTE3(encode[i]), BYTE4(encodoe[i]), BYTE5(encode[i]), BYTE6(encode[i]), HIBYTE(encode[i])]
    key_byte = [LOBYTE(key[i]), BYTE1(key[i]), BYTE2(key[i]), BYTE3(key[i]), BYTE4(key[i]), BYTE5(key[i]), BYTE6(key[i]), HIBYTE(key[i])]
    for j in range(8):
        encode_byte[j] = c_uint8(encode_byte[j] - key_byte[j]).value
        encode_byte[j] ^= 0x28
    tmp = encode_byte[3]
    encode_byte[3] = encode_byte[4]
    encode_byte[4] = tmp
    for j in range(8):
        encode_byte[j] = (encode_byte[j] + j + i * 8) & 0xFF
    tmp = encode_byte[2]
    encode_byte[2] = encode_byte[6]
    encode_byte[6] = tmp
    tmp = encode_byte[1]
    encode_byte[1] = encode_byte[7]
    encode_byte[7] = tmp
    tmp = encode_byte[0]
    encode_byte[0] = encode_byte[5]
    encode_byte[5] = tmp
    for j in range(8):
        print(chr(encode_byte[j]), end='')
# flag{tr@cE_TraC1ng_trAC3d_TRaces_z2CcT8SjWre0op}
```



## PWN

### Memo0

说是pwn不如说是逆向

main函数里有一个login，login成功后会读取`./flag`并输出![image-20240407002519538](https://img.0a0.moe/od/01tklsjzagjiddf6tmlrb33ikbuffbs37v)

在`sub_12E9`显而易见变表base64![image-20240407002913156](https://img.0a0.moe/od/01tklsjzas55opmvvjingjvtqxrv7b37yp)

找到下面比较的字符串，发现并不是base64样式，查找引用找到`sub_1555`在程序初始化时调用，将每个字符的值+1

![image-20240407003814440](https://img.0a0.moe/od/01tklsjzcrhkrd3pfqzfckltq76gc6oqea)

因此可以得到字符串`J8ITC7oaC7ofwTEbACM9zD4mC7oayqY9C7o9Kd==`，通过变表`ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/`解得密码`CTF_is_interesting_isn0t_it?`，连接服务器得到flag![image-20240407004036713](https://img.0a0.moe/od/01tklsjzgqdl34ekqpznciaquy25aut7s3)

## MISC

### WhereIsMyFlag

这道题有点投毒内味了

刚开始以为是git，没找到。仔细审阅文件可以发现`schedule-ics-exporter.py`文件最末端有一串代码![image-20240407013116501](https://img.0a0.moe/od/01tklsjzfrd4twpiw2mjf34nsplen2fcqn)

gz连续解压后得到文件，拖到最末端可得到`flag{760671da3ca23cae060262190c01e575873c72e6}`
