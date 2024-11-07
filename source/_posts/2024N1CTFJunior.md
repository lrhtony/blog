---
title: 2024 N1CTF Junior Reverse
comments: true
date: 2024-02-04 14:33:35
tags:
  - CTF
categories:
  - 技术
---

就做了一题逆向，其他都不会， 是个废物www

![n1ctf_junior](https://img.0a0.moe/od/01tklsjza5eirpvm3pv5e3vorzinsdgrtd)

## 四海流云
### 分析

首先查看基本信息，无壳64位。查看反编译，main函数首先用signal函数挂载了两个handler，然后验证字符串长度，最后进入到magic函数。尝试直接<kbd>F5</kbd>，函数过大，只能看汇编。

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rdx
  void *dest; // [rsp+8h] [rbp-8h]

  signal(11, (__sighandler_t)sigsegv_handler);
  signal(5, (__sighandler_t)sigtrap_handler);
  map_memory();
  puts("Hint for you: https://www.bilibili.com/video/BV19K411S775");
  __isoc99_scanf("%3000s", buf);
  if ( strlen(buf) <= 0x1D )
    __halt();
  if ( !strcmp(buf, "https://www.bilibili.com/video/BV19K411S775") )
    puts("testing the hint...");
  dest = (void *)(322379776 - strlen(buf));
  v3 = strlen(buf);
  memcpy(dest, buf, v3);
  magic(0LL, dest, 0LL, &res);
}
```

同时，我们还能留意到，sigtrap_handler函数用作判断输入是否正确，有两个条件，一个是res=35，另一个是qword_559862087C48要等于一个特殊值。

```c
void __noreturn sigtrap_handler()
{
  __int64 v0; // rbx

  v0 = res - 1;
  if ( v0 == strlen(buf) )
  {
    if ( res == 44 && qword_559862087C48 == 0x81ED1AE544C21AE4LL )// 最后rdx传值
    {
      puts("Have you watched the hint?");
      exit(0);
    }
    if ( res == 35 && qword_559862087C48 == 0x152DF2FED3BC6FDDLL )
    {
      puts("Good job!");
      printf("your flag is ctfpunk{$(echo -n '%s' | sha256sum | cut -d ' ' -f 1)}\n", buf);
      puts(
        "for example, flag for payload 'test' : ctfpunk{9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08}");
      exit(0);
    }
  }
  puts("Try again");
  exit(1);
}
```

通过动调，将hint输入，将res放在rcx，输入dest放在rsi传入magic函数。在magic函数里通过lodsb将输入读出到al，逐个进行比对跳转到程序不同部分。同时还可发现程序在执行到如图位置产生signal=5的信号进入到sigtrap_handler函数进行最后的判断。同时也能在此处得知，最后的res和qword_559862087C48就是这里的rdi和rdx寄存器。rdi记录跳转的次数，也就是字符串的长度，而rdx则要通过一系列计算得到。

![final_addr](https://img.0a0.moe/od/01tklsjzdgai7vbroyfzek4gfl3w4yw3k6)

### 解题

根据提示，我们要找到从函数入口到上面图示位置的最短路径。首先要提取数据。观察即可发现我们要提取的数据为mov rdx的值，cmp的字符以及跳转的偏移。写出提取脚本

```python
import json
from ctypes import *

di = {}
for i in range(0x00005598620691CE, 0x0000559862084187):
#for i in range(0x00005598620691CE, 0x00005598620692ED):
  if (idc.get_wide_byte(i)==0x48) and (idc.get_wide_byte(i+1) == 0xff) and (idc.get_wide_byte(i+2) == 0xc7) and (idc.get_wide_byte(i+3) == 0x48) and (idc.get_wide_byte(i+4) == 0xc7) and (idc.get_wide_byte(i+5) == 0xc0):
    loc_start = i
    print('loc', hex(loc_start))
    di[hex(loc_start)] = []
    mov_rdx = get_wide_dword(i+19)
    print('mov_rdx', hex(mov_rdx))
    di[hex(loc_start)].append(mov_rdx)
    di[hex(loc_start)].append([])
    addr = i+26
    while (get_wide_byte(addr) != 0xac):
      addr += 1
    while True:
      if get_wide_byte(addr) == 0xac:
        addr +=1
      
      elif get_wide_byte(addr) == 0x3c:
        ch = get_wide_byte(addr+1)
        
        if get_wide_byte(addr+2) == 0x0f:  # jz loc_
          jump_addr = get_wide_dword(addr+4)
          jump_addr = c_int32(jump_addr).value
          jump_addr = addr+8+jump_addr
          addr += 8
        
        elif get_wide_byte(addr+2) == 0x74:  # jz short loc_
          jump_addr = get_wide_byte(addr+3)
          jump_addr = c_int8(jump_addr).value
          jump_addr = addr+4+jump_addr
          addr += 4
        print(chr(ch), hex(jump_addr))
        di[hex(loc_start)][1].append([chr(ch), jump_addr])
        
      
      elif get_wide_byte(addr) == 0xf4:  # hlt
        break
      elif get_wide_byte(addr) == 0x00:
        addr += 1
      else:
        print(hex(addr))
        
with open("E:\\a\\ctf\\nu1l\\test.json", 'w') as f:
  f.write(json.dumps(di))
```

提取出数据后，求出由开始地址到目标结束地址所有的最短路径，恰好35也是最短的长度

```python
import json

di = json.loads(open('test.json').read())

final = 0x55986207B194
start = 0x55986206DE09

point_way = {}
path_list = []

def shortest_path(point, length_count, path):
    if length_count > 35:
        return
    if point == final:
        # print(path)
        # print(length_count)
        path_list.append(path)
        return
    if point in path:
        return
    if point not in point_way:
        point_way[point] = []
        point_way[point].append(length_count)
        point_way[point].append(path)
    else:
        if point_way[point][0] >= length_count:
            point_way[point][0] = length_count
            point_way[point][1] = path
        else:
            return
    for item in di[hex(point)][1]:
        shortest_path(item[1], length_count + 1, path + [point])


shortest_path(start, 1, [])
print(1)
with open('path.json', 'w') as f:
    f.write(json.dumps(path_list))
```

然后我这里检查了一下提取的数据，发现提取的move rdx的值有误，反正最短路径也就31623条，而且也是要遍历，不如直接送进程序观察输出

```python
import json
import subprocess

path_list = json.loads(open('path.json').read())
di = json.loads(open('test.json').read())

executable_path = './chall'


for path in path_list:
    path += [0x55986207B194]
    str1 = ''
    for i in range(len(path)-1):
        chs = di[hex(path[i])][1]
        for j in range(len(chs)):
            if chs[j][1] == path[i + 1]:
                str1 += chs[j][0]
                break
    print(str1)
    process = subprocess.Popen(executable_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    process.stdin.write(str1)
    process.stdin.flush()
    output_data, _ = process.communicate()
    if 'Good job' in output_data:
        print(output_data)
        break
```

等一会就能得到结果

```
fjE3z=TecA3S~WD&|bj>`qj)f1:Fl#S775
```

得到flag`ctfpunk{f68d4d21e722d32abcd9af06c895eabfac3303b38de8927a7d5e942f4c2b3921}`