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

## 半决赛-HardTree

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

[HardTree_28464ab375c3023701cbb725d8c63450.zip](https://shamiko-my.sharepoint.com/:u:/g/personal/m_yuru_pro/EVucLgnx63ROiw4Hi4qW6d8B7H6b_9Dpz5vR6uPiciX3fA?e=ftkATR)

## 决赛-withmycat

线下没网没找到合适的Arnold脚本，回去复现一下，发现还挺容易的

先用脚本生成原始图片不同Arnold迭代次数的图片

```python
import cv2
import numpy as np

def arnold_transform(image):
    """Perform one iteration of the Arnold transform on the image."""
    N = image.shape[0]
    new_image = np.zeros_like(image)
    for x in range(N):
        for y in range(N):
            new_x = (x + y) % N
            new_y = (x + 2 * y) % N
            new_image[new_x, new_y] = image[x, y]
    return new_image

def save_images(image, max_iterations, output_prefix):
    """Save images after each iteration of the Arnold transform."""
    transformed_image = np.copy(image)
    for i in range(1, max_iterations + 1):
        transformed_image = arnold_transform(transformed_image)
        output_filename = f"compute/{i}.png"
        cv2.imwrite(output_filename, transformed_image)
        print(f"Saved {output_filename}")

# Load the image
input_image_path = 'img/5.png'  # Replace with your input image path
image = cv2.imread(input_image_path)

if image is None:
    raise ValueError("Image not found or unable to load image.")

# Number of iterations and output prefix
max_iterations = 256
output_prefix = ''

# Save transformed images
save_images(image, max_iterations, output_prefix)
```

然后一张一张图片比较像素，找到相应的迭代次数，然后将迭代次数作为字节写入到文件

```python
from PIL import Image
import numpy as np

imgs = []
for i in range(256):
    img = Image.open(f"compute/{i}.png")
    img = np.array(img)
    imgs.append(img)

write_byte = []
for i in range(802):
    img = Image.open(f"img/{i}.png")
    img = np.array(img)
    for j in range(256):
        if np.array_equal(img, imgs[j]):
            write_byte.append(j)
            break

with open("flag", "wb") as f:
    f.write(bytes(write_byte))
```

使用`file`命令判断文件类型是zip，打开，文本文件中得到`flag{cb6a1dc1-3367-4ca0-b1ea-859cf696fcd3}`

在找Arnold脚本时发现中间对x、y的变换算法各有各的不同，现场仅有的脚本没能跑出来也是这个原因，主要是x和y的系数不同，怎么找到准确的系数解出题目也是一个问题

[withmycat_271d42ddcca3fae2c7ed2ed74051a73b.7z](https://shamiko-my.sharepoint.com/:u:/g/personal/m_yuru_pro/EVycAyvxiW5EmETwCfxnyZoBb2qn2Y2iNV6NrbQvX08rEA?e=TactxB)
