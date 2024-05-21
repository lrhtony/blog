---
title: 2024 数字中国创新大赛数字安全赛道 部分题目wp
comments: true
date: 2024-05-21 16:50:47
tags:
  - CTF
categories:
  - 技术
cover: https://img.jks.moe/od/01tklsjzbx3vmxhujafjazoxpahcloib3v
---

> 封面：[pixiv@海月ヨル](https://www.pixiv.net/artworks/118919349)

## HardTree

通过IDA分析文件，阅读汇编代码，可知程序首先校验开头的"flag{"，然后进入下面进行进一步的判断。在下面通过比较输入的是"l"还是"r"，从而决定跳转第一个还是第二个地址。地址存储于堆中。每次比较堆的地址+10是否等于0x074EBD15，从而判断是否成功

因此可以得知该程序是一个迷宫问题。通过动态调试可以知道该迷宫起点为`heap_base_addr+0xbf87a0`，终点为`heap_base_addr+0xBF7D80`，该地址+0x10的值即为0x074EBD15

通过动调，在生成迷宫后使用脚本dump出堆

```c
auto i,fp;
fp = fopen("E:\\a\\ctf\\shuzi\\HardTree_heap.dmp","wb");
for (i = 0x0000562CF20A8000; i <= 0x0000562CF2CA4FFF; i++)
     fputc(Byte(i),fp);
```

然后使用脚本对路径进行搜索

```python
base_addr = 0x562CF20A8000
start_addr = 0x562CF2CA07A0 - base_addr
end_addr = 0xBF7D80  # 0x074EBD15位置-0x10

dump_file = open('HardTree_heap.dmp', 'rb')
file = dump_file.read()

def bytes_to_addr(byte_str):
    num = 0
    for ch in byte_str[::-1]:
        num *= 256
        num += ch
    return num

have_node = []
node_path = []

def read_node(node):
    if node not in have_node:
        if node == end_addr:
            print('flag{'+''.join(node_path)+'}')
            exit()
        have_node.append(node)
        # print(node)
        r_node = bytes_to_addr(file[node:node + 8]) - base_addr
        l_node = bytes_to_addr(file[node + 8:node + 16]) - base_addr
        if r_node != 0:
            node_path.append('r')
            read_node(r_node)
            node_path.pop()
        if l_node != 0:
            node_path.append('l')
            read_node(l_node)
            node_path.pop()
        have_node.pop()

read_node(start_addr)
# flag{llllllllllllllrlrllrllllrrlrlrlrlllrllrlllrllllllrr}
```

验证

![image-20240521164545050](https://img.jks.moe/od/01tklsjzapjmr2pg5qgzhley23xklarv3d)

该题的难点主要在于前面巨大的生成迷宫代码，给逆向及动调都带来了麻烦。不过耐心点还是可以动调看汇编看出原理的。算不上特别难，但需要有阅读汇编的能力和足够的耐心。