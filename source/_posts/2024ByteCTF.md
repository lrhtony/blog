---
title: 2024ByteCTF Reverse BabyAPK
comments: true
date: 2024-09-22 19:52:29
tags:
  - CTF
categories:
  - 技术
cover: https://img.jks.moe/od/01tklsjzgbdnstmw5wxjbyknn4nwrijxuj
---

大家都好有实力{{'{'}}{{'{'}}(>_<){{'}'}}{{'}'}}，就只做出babyapk

## 分析

拿到题这都是啥啊，平时没怎么做安卓逆向，对flutter更是啥都不清楚，只知道Jadx分析再将lib拖入IDA分析。可以留意到Jadx里面的类和函数基本上是单双字母命名，分析不出什么，libapp.so里面能够搜索到`wrong flag`、`ByteCTF{`等相关字符串，但无法查找引用找到相关函数。

于是乎上网搜了一下flutter逆向，找到[Blutter](https://github.com/worawit/blutter)，通过这个程序简单恢复了一下libapp.so里面的函数表，然后根据网上的教程想通过`onTap`相关函数找到逻辑，但基本上都是与UI相关，找不到加密验证这些代码。用Frida hook了几个函数也只能够

又留意到lib文件内还有个`librust_lib_babyapk.so`，搜索得知flutter_rust_bridge这项技术，猜测加密在这个lib内，留意到`m3n4b5v6`可疑，该字符串也存在于libapp.so内，但hook相关函数无果。打算使用Frida hook所有函数，提取所有函数地址，使用脚本生成所有hook函数

```python
with open('addr.txt', 'r') as f:
    data = f.readlines()

script = '''
var addr = Module.getBaseAddress("librust_lib_babyapk.so").add(0x{{addr}})
Interceptor.attach(addr, {
    onEnter: function (args) {
      console.log("Hooking the {{addr}} function");
    },
    onLeave: function (retval) {
        // Modify or log return value if needed
    }
});
'''

f = open('script.js', 'w')
for line in data:
    print(script.replace('{{addr}}', line.strip()))
    f.write(script.replace('{{addr}}', line.strip()))
f.close()
```

输入`ByteCTF{uuid}`格式flag，成功打印出调用函数列表，一个个筛选，最后发现+0x3AEE0(arm64) +0x3C660(x86)的函数最可疑

```javascript
var addr = Module.getBaseAddress("librust_lib_babyapk.so").add(0x3aee0)
Interceptor.attach(addr, {
    onEnter: function (args) {

      console.log("Hooking the 3aee0 function");
      console.log(args[0]);
      var ptr1 = ptr(args[0]);
      console.log(Memory.readByteArray(ptr1, 0x24));
      console.log(args[1]);

    },
    onLeave: function (retval) {
        // Modify or log return value if needed
    }
});
```

打印出传入参数

![image-20240924231927466](https://img.jks.moe/od/01tklsjzf3el2raugt7rek2mrgasaxf7js)

可见正是传入的flag中间部分。对该函数使用IDA进行动调，可以发现上面部分没用（可能是校验是否是uuid格式？），加密主要是下面部分![image-20240924232115145](https://img.jks.moe/od/01tklsjzb2s5hd5vqq7bbi3pwui7gfreh7)

然后对这块部分写脚本即可得到flag。解方程本应用z3来解，但不知为何解不出，最后直接暴力跑了

## 解题

```c
#include <stdio.h>

char table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
int encoded[32] = {
    0x0001EE59, 0x0000022A, 0x00001415, 0x00040714, 0x000013E0, 0x000008B8, 0xFFFDCEA0, 0x0000313B, 
    0x0003D798, 0xFFFFFE6B, 0x00000C4E, 0x00023884, 0x0000008D, 0x00001DB4, 0xFFFC1328, 0x00001EAC, 
    0x00043C64, 0x0000142B, 0xFFFFF622, 0x00023941, 0xFFFFEF6D, 0x0000120C, 0xFFFBD30F, 0x00001EBE, 
    0x00045158, 0xFFFFEF66, 0x00001D3F, 0x0004C46B, 0xFFFFF97A, 0x00001BFD, 0xFFFBA235, 0x00001ED2};

int main()
{
    for (int i = 0; i < 4; i++) {
        for (int i1 = 0; i1 < 16; i1++) {
            for (int i2 = 0; i2 < 16; i2++) {
                for (int i3 = 0; i3 < 16; i3++) {
                    for (int i4 = 0; i4 < 16; i4++) {
                        for (int i5 = 0; i5 < 16; i5++) {
                            for (int i6 = 0; i6 < 16; i6++) {
                                for (int i7 = 0; i7 < 16; i7++) {
                                    for (int i8 = 0; i8 < 16; i8++) {
                                        char c1 = table[i1], c2 = table[i2], c3 = table[i3], c4 = table[i4], c5 = table[i5], c6 = table[i6], c7 = table[i7], c8 = table[i8];
                                        if (c8 + c4 * c2 * c6 - (c3 + c7 + c1 * c5) == encoded[i*8]) {
                                            if (c2 - c5 - c3 * c6 + c8 * c4 + c1 + c7 == encoded[i*8+1]) {
                                                if (c3 * c6 - (c5 + c8 * c4) + c1 + c7 * c2 == encoded[i*8+2]) {
                                                    if (c4 + c5 * c3 - (c8 + c1) + c7 * c6 * c2 == encoded[i*8+3]) {
                                                        if (c6 * c2 + c4 + c1 * c5 - (c7 + c8 * c3) == encoded[i*8+4]) {
                                                            if (c3 * c6 + c4 * c2 + c1 - (c7 + c5 * c8) == encoded[i*8+5]) {
                                                                if (c8 - c4 + c1 * c6 + c7 - c5 * c3 * c2 == encoded[i*8+6]) {
                                                                    if (c2 - c8 - (c4 + c6) + c5 * c3 + c7 * c1 == encoded[i*8+7]) {
                                                                        printf("%c%c%c%c%c%c%c%c", c3, c4, c1, c2, c5, c6, c7, c8);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
```

得到`32e750c8fb214562af22973fb5176b9c`，转成flag格式`ByteCTF{32e750c8-fb21-4562-af22-973fb5176b9c}`

<img src="https://img.jks.moe/od/01tklsjzf3rt2n6ez3hjdyngbdenh3ro24" alt="d5989def95feb7e40ae3f6ae4d4a896" style="zoom:50%;" />

## 复盘

这次这道题主要卡在如何找到加密函数上面，我通过调试、Frida hook等方法，直到最后把所有函数hook上一个个分析才找到加密函数

看了一下其他队伍的wp，有通过Frida报错爆出调用链的(Nepnep)

![image-20240924235258722](https://img.jks.moe/od/01tklsjzbnnyhm27nwb5gyjwv73hl5vy74)

有通过[flutter_rust_bridge](https://pub.dev/packages/flutter_rust_bridge)代码分析的(W&M)

![image-20240924235654423](https://img.jks.moe/od/01tklsjzhydmaeaqobzjgj7nt5tqmyvita)

还有直接从libapp.so直接分析的(Arr3stY0u)

![image-20240925001813090](https://img.jks.moe/od/01tklsjzegnwti2ysbyjfieeosufja7owe)
