---
title: 2024 ciscn 初赛
comments: true
date: 2024-05-20 00:50:47
tags:
  - CTF
categories:
  - 技术
cover: https://img.jks.moe/od/01tklsjzeuadpiikx2enhy53bbtwifp7mt
---

> 封面：[X@ryoutanf](https://x.com/ryoutanf/status/1630775568148074496)

算是正式比赛中做得比较舒服的一次，记录一下自己做出来的题。

>  队里逆向怎么就只有我一个/(ㄒoㄒ)/~~

## Misc

### 火锅链观光打卡

连接钱包，答题，兑换NFT即可获得![img](https://img.jks.moe/od/01tklsjzer6uxtkad3wzgy3c2hrbwatazm)

后面想用blockchain browser通过rpc去查看链上记录，好像不行

顺便一提这图一眼AI作的，好几个逻辑有问题的地方

### Power Trajectory Diagram

这道题要通过功耗信息泄漏来找到密码，给了个numpy的文件，根据里面的index和input，可以得知是每一位的密码都将40个字符全部试一遍，然后trace是相应的功率曲线。

每个索引位置求平均值又看不出什么，也不会什么统计学之类的，干脆就直接把点全部打出来，再把图中最突出的那部分单独打印

```python
import numpy as np
from matplotlib import pyplot as plt

datas = np.load('attachment.npz')

for i in range(80, 120):
    # 将第i个trace的点作图
    plt.plot(datas['trace'][i][300:500])
    plt.title(datas['input'][i])
    plt.show()
```

![image-20240520012016582](https://img.jks.moe/od/01tklsjzbs5s3ylawmxzd3youjmqgnfj2n)

![image-20240520012024713](https://img.jks.moe/od/01tklsjzacfz5g4zjzpjf26jlaixrf6i4f)

![image-20240520012032452](https://img.jks.moe/od/01tklsjzf5mrmdqp4zkncig3r6ah4f5tch)

这样一来就能明显看出该位密码是c，循环此步骤最后得到`flag{_ciscn_2024_}`

## Reverse

### asm_re

文件是IDA逆向后得到的汇编代码。这里偷了个懒，直接丢给ChatGPT，也算是体验了GPT-4o的强大

![image-20240520012651462](https://img.jks.moe/od/01tklsjzd7wl6mihkc4jgyiqmwbna4zpcr)

```python
data = [0x1fd7, 0x21b7, 0x1e47, 0x2027, 0x26e7, 0x10d7, 0x1127, 0x2007, 0x11c7, 0x1e47, 0x1017, 0x1017, 0x11f7, 0x2007, 0x1037, 0x1107, 0x1f17, 0x10d7, 0x1017, 0x1017, 0x1f67, 0x1017, 0x11c7, 0x11c7, 0x1017, 0x1fd7, 0x1f17, 0x1107, 0x0f47, 0x1127, 0x1037, 0x1e47, 0x1037, 0x1fd7, 0x1107, 0x1fd7, 0x1107, 0x2787]
for ch in data:
    print(chr((((ch - 0x1e) ^ 0x4d) - 0x14) // 0x50), end='')
# flag{67e9a228e45b622c2992fb5174a4f5f5}
```

### androidso_re

使用jadx查看，在`MainActivity`的`legal`函数中限制的flag长度为38，并将括号中间部分送入`inspect.inspect`进行验证。在该函数内通过调用静态库`getiv`和`getkey`获取相应的iv和key，将部分flag作为明文通过AES DES/CBC/PKCS5Padding模式加密后与密文进行比较验证。

用IDA分析x86_64下的libSecret_entrance.so文件，发现代码经过混淆，难以阅读，故尝试动调获取。但发现在真机和模拟器上均在验证flag时闪退，无法动调获取函数返回值。

此时再观察题目描述

> Here are only the corresponding So files for the ARM architecture

对ARM架构的so文件进行分析，发现armeabi-v7a的so文件未经过混淆，分析

iv函数：

```c
int __fastcall getiv_fixed(int a1)
{
  int v2; // r0
  char v4[12]; // [sp+4h] [bp-2Ch] BYREF
  char v5[12]; // [sp+10h] [bp-20h] BYREF

  std::string::basic_string<decltype(nullptr)>((int)v5, "F2IjBOh1mRW=");
  gege((int)v4, (int)v5, 10);                   // 大小写各自凯撒向左位移10，得V2YzREx1cHM=
  v2 = std::operator<<<char>(&std::cout, v4);
  sub_278A(v2);
  didi(a1, v4);                                 // base64解码，得Wf3DLups
  std::string::~string(v4);
  std::string::~string(v5);
  return _stack_chk_guard;
}
```

key函数：

```c
int __fastcall Java_com_example_re11113_jni_getkey(int a1)
{
  int v2; // r3
  int i; // r0
  _BYTE *v4; // r2
  _DWORD *v5; // r0
  _BYTE *v6; // r1
  int v7; // r4
  unsigned __int8 v9; // [sp+0h] [bp-40h] BYREF
  _BYTE v10[11]; // [sp+1h] [bp-3Fh] BYREF
  unsigned __int8 v11; // [sp+Ch] [bp-34h] BYREF
  _BYTE v12[11]; // [sp+Dh] [bp-33h] BYREF
  unsigned __int8 v13[12]; // [sp+18h] [bp-28h] BYREF

  std::string::basic_string<decltype(nullptr)>((int)v13, "TFSecret_Key");// RC4_value
  std::string::basic_string<decltype(nullptr)>((int)&v9, "YourRC4Key");// RC4_key
  jiejie(&v11, v13, (int)&v9, v2);              // 就是一个标准RC4加密
  std::string::~string((int)&v9);
  for ( i = 0; i != 8; ++i )
  {
    v4 = *(_BYTE **)&v12[7];
    if ( !(v11 << 31) )
      v4 = v12;
    v4[i] ^= byte_23A4[4 * i];                  // 结果异或
  }
  sub_2A5C();
  v5 = (_DWORD *)std::operator<<<std::char_traits<char>>((int)&std::cout, "Keys match!");
  sub_278A(v5);
  v6 = *(_BYTE **)&v10[7];
  if ( !(v9 << 31) )
    v6 = v10;
  v7 = (*(int (__fastcall **)(int, _BYTE *))(*(_DWORD *)a1 + 668))(a1, v6);
  std::string::~string(&v9);
  std::string::~string(&v11);
  std::string::~string(v13);
  return v7;
}
```

![屏幕截图 2024-05-19 163919](https://img.jks.moe/od/01tklsjzdye4l5psib6vdittea36cqmn35)

![屏幕截图 2024-05-19 163942](https://img.jks.moe/od/01tklsjza2w2zex7eld5gjx3cf4ftszdp4)

因此通过iv:`Wf3DLups`,key:`A8UdWaeq`解`JqslHrdvtgJrRs2QAp+FEVdwRPNLswrnykD/sZMivmjGRKUMVIC/rw==`得`188cba3a5c0fbb2250b5a2e590c391ce`

因此`flag{188cba3a5c0fbb2250b5a2e590c391ce}`

### whereThel1b

第一次做pyd的题目。拿到题目后才知道Python还有这种玩法，网上能够搜到的资料也不多。自己首先在Python3.10里面运行，注释掉`whereThel1b.whereistheflag(flag)`，发现输出的`ret`不变，因此就只分析`trytry`函数去了。通过调试可以发现程序进入了`random.seed`, `base64.b64encode`, `random.randint`等函数，并且b64encode时传入的是flag，randint传入的是0到flag长度。除此之外内部的加密逻辑仍然未知。

通过AI分析和阅读IDA逆向后的源码，也可发现程序在`trytry`中调用了`random.seed`和`whereistheflag1`，`whereistheflag1`中调用`base64.b64encode`, `random.randint`,`PyNumber_Xor`等。无奈得出大概的算法也没能成功解出。但通过fuzz和加密过程的分析，我们发现可以利用base64的特性3个字符对应4个字符进行爆破。对第4-6位进行测试验证可行性得到`g{7`，因此我直接写出爆破脚本

```python
import whereThel1b
encry = [108, 117, 72, 80, 64, 49, 99, 19, 69, 115, 94, 93, 94, 115, 71, 95, 84, 89, 56, 101, 70, 2, 84, 75, 127, 68, 103, 85, 105, 113, 80, 103, 95, 67, 81, 7, 113, 70, 47, 73, 92, 124, 93, 120, 104, 108, 106, 17, 80, 102, 101, 75, 93, 68, 121, 26]

flag = 'flag{7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}'
chr_list = '0123456789abcdef-{}'

for i in range(6, 42, 3):
    found = False
    for ch1 in chr_list:
        if found:
            break
        for ch2 in chr_list:
            if found:
                break
            for ch3 in chr_list:
                flag_copy = flag[:i] + ch1 + ch2 + ch3 + flag[i+3:]
                flag_copy = flag_copy.encode()
                whereThel1b.whereistheflag(flag_copy)
                ret = whereThel1b.trytry(flag_copy)
                if ret[:((i//3)+1)*4] == encry[:((i//3)+1)*4]:
                    print(flag_copy)
                    flag = flag_copy.decode()
                    found = True
                    break
# flag{7f9a2d3c-07de-11ef-be5e-cf1e88674c0b}
```

更新： 在看了别人的wp后发现加密逻辑没分析错，不知道为什么长度56写成了55，这里也贴一下修改后正确的

```python
import random
import base64

encry = [108, 117, 72, 80, 64, 49, 99, 19, 69, 115, 94, 93, 94, 115, 71, 95, 84, 89, 56, 101, 70, 2, 84, 75, 127, 68, 103, 85, 105, 113, 80, 103, 95, 67, 81, 7, 113, 70, 47, 73, 92, 124, 93, 120, 104, 108, 106, 17, 80, 102, 101, 75, 93, 68, 121, 26]

random.seed(0)
encode_list = [0 for _ in range(56)]
rand_list = []
for i in range(56):
    rand_list.append(random.randint(0, 56))

for i in range(56):
    encode_list[i] = encry[i] ^ rand_list[i]

print(encode_list)
base64_str = ''
for i in range(56):
    base64_str += chr(encode_list[i])
print(base64_str)

decode = base64.b64decode(base64_str)
print(decode)
# flag{7f9a2d3c-07de-11ef-be5e-cf1e88674c0b}
```


### gdb_debug

这道题没想明白，可能有什么忽略了，按照静态分析解出来的都是乱码。题目描述是动静结合，但我动态调试查看过rand的数都没问题，还请高人指点。

```python
s2 = "congratulationstoyoucongratulationstoy"
encode = [ord(i) for i in s2]
xor_data = [0xBF, 0xD7, 0x2E, 0xDA, 0xEE, 0xA8, 0x1A, 0x10, 0x83, 0x73, 0xAC, 0xF1, 0x06, 0xBE, 0xAD, 0x88, 0x04, 0xD7, 0x12, 0xFE, 0xB5, 0xE2, 0x61, 0xB7, 0x3D, 0x07, 0x4A, 0xE8, 0x96, 0xA2, 0x9D, 0x4D, 0xBC, 0x81, 0x8C, 0xE9, 0x88, 0x78]
rand_data = [0x1fae43d9, 0x14da3e0f, 0x29fdc718, 0x6b7956bd, 0x565247c7, 0x118e4e16, 0xec41481, 0x2853f3be, 0x18fe7af8, 0x637a7d4a, 0x4c235f65, 0x1a636af2, 0xf8e55d, 0x3f4562ab, 0x910412b, 0x57ec233, 0x1a9fe4d4, 0x321373a5, 0x5aa40d67, 0x7661698, 0x7e44749f, 0x3c64e7e, 0x49be3e2b, 0x394c025d, 0x6acb9dc2, 0x726285af, 0x7d6818e, 0x655c983a, 0x7afa9e4c, 0x7f7af6a5, 0x5b28f175, 0x1aa8e225, 0x145534b4, 0x526b88d, 0x62238e3, 0x6aa77c7b, 0x16b506a3, 0x14e64d64, 0x12fb7039, 0x2fb3819c, 0x7860caae, 0x5f1ecf9e, 0x4a16ec8e, 0x7959b00b, 0x1e64324a, 0x53272db9, 0x7ed8723f, 0x3904171e, 0x53aa15e, 0x597c7fa6, 0x406a2db6, 0x37f15fd, 0x5d42ce25, 0xa286be1, 0x3ccb185a, 0x480e6be7, 0x7c8af191, 0x44a199e8, 0x2d6b0421, 0x77858fdd, 0x441c908d, 0x893f596, 0x122e7202, 0x5871c541, 0xdbaae23, 0x1850aae5, 0x431941bc, 0x246fb4c7, 0x2d36f849, 0x5614b1f5, 0x54233663, 0x2597c2f7, 0x35338194, 0x1e3a22f1, 0x1ef17303, 0x5397b3de, 0x716150aa, 0x1dc9e542, 0xc9bcafc, 0x769bf209, 0x774664e8, 0x4d05f8b2, 0x7a1b0806, 0x5489330d, 0x572e6493, 0x36e62061, 0x1c979ef4, 0x53b95624, 0x7b87ba49, 0x4a02a315, 0x4b3ee601, 0x3fa44ad7, 0x529698ab, 0x5d6d5804, 0x18161018, 0x605146cf, 0x75be02e9, 0x5b2f51d5, 0x4c0fb96, 0x22f4fb33, 0x314403ca, 0x58e431f9, 0x488cbe2a, 0x6677855e, 0x771e54ea, 0x677e312d, 0x3a0f393c, 0x687fa594, 0x548166f, 0x46ab0438, 0x5f1b979d, 0x7c8e7b58, 0x13b0fcea, 0x59369fa4]

for i in range(len(encode)):
    encode[i] ^= xor_data[i]

for i in range(len(encode)):
    encode[i] ^= (rand_data[75+i] & 0xff)

ptr = [j for j in range(38)]
for k in range(37, 0, -1):
    # v18 = rand_data[38+k] % (k+1)  # 6
    v18 = rand_data[75-k] % (k+1)
    v19 = ptr[k]
    ptr[k] = ptr[v18]
    ptr[v18] = v19

encode2 = [0 for i in range(38)]
for i in range(38):
    encode2[ptr[i]] = encode[i]

for i in range(38):
    encode2[i] ^= (rand_data[i] & 0xff)

for i in range(38):
    print(chr(encode2[i]), end='')
# flag{78bace5989660ee38f1fd980a4b4fbcd}
```

发现问题，引以为戒
