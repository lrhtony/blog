---
title: DubheCTF 2024 Reverse
comments: true
date: 2024-03-23 18:46:54
tags:
  - CTF
categories:
  - 技术
---

纯坐牢，赛后复盘

## Destination

上来拖入IDA，在汇编中即可看见在输入后触发异常进入SEH

![image-20240323192805475](https://img.jks.moe/od/01tklsjzdjm2w33i4nm5gzmzrlanryxq7f)

尝试动调，闪退，寻找反调试。这里我通过勾选进程开始时断点来逐步运行寻找，哪里结束就进去。![image-20240323194043019](https://img.jks.moe/od/01tklsjzgcaarkkfskbng3u47gscugadre)

最后发现是在地址`0x00418279`处有个`j__initterm`，查找可知该函数通过传入开始和结束两个地址，然后逐个运行其中的函数。在这个地址区间首先有`?pre_cpp_initialization@@YAXXZ`，然后后面有3个函数，多多少少都和反调试有点关系，因此我直接在外面把`j__initterm`patch掉。然后还有`0x0041B3AB`有个`IsProcessorFeaturePresent`，把下面`jnz     short loc_41B3BC`nop掉，基本上反调试就处理完了。

动调跟随进入`0x4140D7`，可以发现这里代码有混淆。动调跟踪即可发现这里是将汇编每行拆开，然后跳转到下一个地方继续执行。![image-20240323235603176](https://img.jks.moe/od/01tklsjzbcarwf5bm7srb3fwdl7nkjhf7l)

第一行是相应的汇编，中间三行为无用花指令，直接改成`nop`，下面为跳转，由于是`jz`和`jnz`，会导致下面不会运行的内容也被识别成代码，为了方便分析，我这里直接将其patch成`jmp`。我这里手动进行patch，工作量还行，其实应该用脚本的。

patch完成后IDA可以直接构建函数同时反编译出代码![image-20240324000135955](https://img.jks.moe/od/01tklsjzhbmydqjvuzfzbiklm3zppidoxc)

优化一下就变成

```c
int __usercall sub_4143A6@<eax>(int base_address@<ebp>)
{
  int result; // eax
  int *counter = (int *)(base_address - 8);
  int *value1 = (int *)(base_address - 68);
  int *value2 = (int *)(base_address - 56);
  int *index = (int *)(base_address - 32);
  int *inner_counter = (int *)(base_address - 20);
  int *temp_value = (int *)(base_address - 44);
  int *calculated_value = (int *)(base_address - 268);

  *counter = 50;
  *value1 = 0;
  *value2 = dword_4234A8[11];

  do
  {
    *value1 -= 0x5B4B9F9E;
    *index = (*value1 >> 2) & 3;

    for (*inner_counter = 0; *inner_counter < 11; ++*inner_counter)
    {
      *temp_value = dword_4234A8[*inner_counter + 1]; // 使用 dword_4234A8 的后一个数
      *calculated_value = (((*value2 ^ dword_42309C[*index ^ *inner_counter & 3])
                          + (*temp_value ^ *value1)) ^ (((16 * *value2) ^ (*temp_value >> 3))
                          + ((4 * *temp_value) ^ (*value2 >> 5))))
                          + dword_4234A8[*inner_counter];
      dword_4234A8[*inner_counter] = *calculated_value;
      *value2 = *calculated_value;
    }

    *temp_value = dword_4234A8[0];
    *calculated_value = (((*value2 ^ dword_42309C[*index ^ *inner_counter & 3])
                        + (*temp_value ^ *value1)) ^ (((16 * *value2) ^ (*temp_value >> 3))
                        + ((4 * *temp_value) ^ (*value2 >> 5))))
                        + dword_4234A8[11];
    dword_4234A8[11] = *calculated_value;
    *value2 = *calculated_value;

    result = *counter - 1;
    *counter = result;
  }
  while (result);

  return 1;
}
```

可以看出这是个XXTEA。通过动调可知输入先通过XXTEA加密了两次，然后到下面jump进去后又加密一次

![image-20240324002258209](https://img.jks.moe/od/01tklsjzfyu4sxlvkf2nhi35baobh2oztn)

但是根据IDA显示的地址跟踪进去只是垃圾数据，尝试在`0x4142A7`下断点也不行，尝试在input数据那里下断点，也仅仅能断下来，并不能定位到程序运行到的地址。后来看其他队伍的wp得知这里是“天堂之门”的技术。

首先是跳转地址应为`0x413F77`，这点在其他调试器里可以看到![image-20240324104003366](https://img.jks.moe/od/01tklsjzdnqgbwyl6v7ff3taifju2dcq37)

而我们把断点设置在`0x413F77`时，也能够断下来，但由于是64位的缘故，并不能直接动调，直接分析也有错误。我们需要把这段dump下来使用64位IDA进行分析。

![image-20240324104449307](https://img.jks.moe/od/01tklsjzfjzai5oe4qybczmru4ops2qt4u)

经验证这是第三次加密。加密流程确定好就能写出解密脚本

```python
import ctypes
from Crypto.Util.number import long_to_bytes

key = [0x6B0E7A6B, 0xD13011EE, 0xA7E12C6D, 0xC199ACA6]
encode = [0xA790FAD6, 0xE8C8A277, 0xCF0384FA, 0x2E6C7FD7, 0x6D33968B, 0x5B57C227, 0x653CA65E, 0x85C6F1FC, 0xE1F32577, 0xD4D7AE76, 0x3FAF6DC4, 0x0D599D8C]

for i in range(12):
    v1 = ctypes.c_uint32(encode[i])
    for j in range(32):
        if v1.value & 1 == 0:
            v1.value >>= 1
        else:
            v1.value ^= 0x84A6972F
            v1.value >>= 1
            v1.value |= 1 << 31
    encode[i] = v1.value


counter = 50
value1 = ctypes.c_uint32(-0x5B4B9F9E*50)
value2 = ctypes.c_uint32(0)
calculated_value = ctypes.c_uint32(0)
while counter > 0:
    index = (value1.value >> 2) & 3

    calculated_value.value = encode[11]
    value2.value = encode[10]
    temp_value = encode[0]

    encode[11] = (calculated_value.value - (((value2.value ^ key[index ^ 11 & 3]) + (temp_value ^ value1.value)) ^ (((16 * value2.value) ^ (temp_value >> 3)) + ((4 * temp_value) ^ (value2.value >> 5))))) & 0xFFFFFFFF

    for inner_counter in range(10, 0, -1):
        calculated_value.value = encode[inner_counter]
        value2.value = encode[inner_counter - 1]
        temp_value = encode[inner_counter + 1]
        encode[inner_counter] = (calculated_value.value - (((value2.value ^ key[index ^ inner_counter & 3]) + (temp_value ^ value1.value)) ^ (((16 * value2.value) ^ (temp_value >> 3)) + ((4 * temp_value) ^ (value2.value >> 5))))) & 0xFFFFFFFF

    calculated_value.value = encode[0]
    value2.value = encode[11]
    temp_value = encode[1]

    encode[0] = (calculated_value.value - (((value2.value ^ key[index ^ 0 & 3]) + (temp_value ^ value1.value)) ^ (((16 * value2.value) ^ (temp_value >> 3)) + ((4 * temp_value) ^ (value2.value >> 5))))) & 0xFFFFFFFF

    value1.value += 0x5B4B9F9E
    counter -= 1

counter = 50
value1 = ctypes.c_uint32(-0x5B4B9F9E*50)
value2 = ctypes.c_uint32(0)
calculated_value = ctypes.c_uint32(0)
while counter > 0:
    index = (value1.value >> 2) & 3

    calculated_value.value = encode[11]
    value2.value = encode[10]
    temp_value = encode[0]

    encode[11] = (calculated_value.value - (((value2.value ^ key[index ^ 11 & 3]) + (temp_value ^ value1.value)) ^ (((16 * value2.value) ^ (temp_value >> 3)) + ((4 * temp_value) ^ (value2.value >> 5))))) & 0xFFFFFFFF

    for inner_counter in range(10, 0, -1):
        calculated_value.value = encode[inner_counter]
        value2.value = encode[inner_counter - 1]
        temp_value = encode[inner_counter + 1]
        encode[inner_counter] = (calculated_value.value - (((value2.value ^ key[index ^ inner_counter & 3]) + (temp_value ^ value1.value)) ^ (((16 * value2.value) ^ (temp_value >> 3)) + ((4 * temp_value) ^ (value2.value >> 5))))) & 0xFFFFFFFF

    calculated_value.value = encode[0]
    value2.value = encode[11]
    temp_value = encode[1]

    encode[0] = (calculated_value.value - (((value2.value ^ key[index ^ 0 & 3]) + (temp_value ^ value1.value)) ^ (((16 * value2.value) ^ (temp_value >> 3)) + ((4 * temp_value) ^ (value2.value >> 5))))) & 0xFFFFFFFF

    value1.value += 0x5B4B9F9E
    counter -= 1

for i in range(12):
    print(long_to_bytes(encode[i]).decode()[::-1], end='')
# DubheCTF{82e1e3f8-85fe469f-8499dd48-466a9d60}
```

## ezVK

IDA进去后就看到调用了一堆API，查了一下得知是Vulkan，大概意思是读取`ezVK`这个资源文件运行，将输入送进去，再将结果取出来对比。用die提取文件

```bash
$ file ezVK_dump
ezVK_dump: Khronos SPIR-V binary, little-endian, version 0x010000, generator 0x08000b
```

在网上找到工具[SPIRV-Cross](https://github.com/KhronosGroup/SPIRV-Cross)，下载下来用Cmake编译，参考里面的CLI，运行

```bash
./spirv-cross --version 310 --es ezVK_dump
```

得到魔改XTEA

```glsl
#version 310 es
layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;

const uint _80[5] = uint[](1214346853u, 558265710u, 559376756u, 1747010677u, 1651008801u);

layout(binding = 0, std430) buffer V
{
    uint v[];
} _23;

void main()
{
    uint cnt = gl_GlobalInvocationID.x * 2u;
    uint sum = 0u;
    uint l = _23.v[cnt];
    uint r = _23.v[cnt + 1u];
    for (int i = 1; i <= 40; i++)
    {
        l += ((((((~(r << uint(3))) & (r >> uint(5))) | ((r << uint(3)) & (~(r >> uint(5))))) ^ (~r)) & ((r << uint(3)) ^ (r >> uint(5)))) ^ ((~((~(sum + _80[sum & 4u])) | (~((r >> uint(3)) & (r << uint(2)))))) & (l | (~l))));
        sum += 1932555628u;
        r += ((((((~(l << uint(3))) & (l >> uint(5))) | ((l << uint(3)) & (~(l >> uint(5))))) ^ (~l)) & ((l << uint(3)) ^ (l >> uint(5)))) ^ ((~((~(sum + _80[(sum >> uint(11)) & 4u])) | (~((l >> uint(3)) & (l << uint(2)))))) & (r | (~r))));
    }
    _23.v[cnt] = l;
    _23.v[cnt + 1u] = r;
}
```

由此可以写出解题脚本

```python
from ctypes import *
from Crypto.Util.number import long_to_bytes

key = [1214346853, 558265710, 559376756, 1747010677, 1651008801]
encode = [0x185B72AF, 0x0631D2C6, 0xDE8B33CC, 0x31EBCD9F, 0x05DB8B33, 0x0A8D77D0, 0x865C6111, 0xBF032335, 0x722228A5, 0xAD833A57, 0xB7C3456F, 0]

for i in range(len(encode) // 2):
    sum_num = c_uint32(1932555628 * 40)
    l = c_uint32(encode[i * 2])
    r = c_uint32(encode[i * 2 + 1])
    for j in range(40):
        r.value -= ((((((~(l.value << 3)) & (l.value >> 5)) | ((l.value << 3) & (~(l.value >> 5)))) ^ (~l.value)) & ((l.value << 3) ^ (l.value >> 5))) ^ (~((~(sum_num.value + key[(sum_num.value >> 11) & 4])) | (~((l.value >> 3) & (l.value << 2))))))
        sum_num.value -= 1932555628
        l.value -= ((((((~(r.value << 3)) & (r.value >> 5)) | ((r.value << 3) & (~(r.value >> 5)))) ^ (~r.value)) & ((r.value << 3) ^ (r.value >> 5))) ^ (~((~(sum_num.value + key[sum_num.value & 4])) | (~((r.value >> 3) & (r.value << 2))))))

    encode[i * 2] = l.value
    encode[i * 2 + 1] = r.value

for i in range(len(encode)):
    print(str(long_to_bytes(encode[i]))[2:-1][::-1], end='')
# DubheCTF{Go0Od!!!You_4re_Vu1k@N_Mast3r^^
```

由长度42可以爆破倒数第二位得到`DubheCTF{Go0Od!!!You_4re_Vu1k@N_Mast3r^^_}`

## Others

其他的再研究一下