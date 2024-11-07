---
title: 进一步了解base64
comments: true
date: 2023-12-24 16:39:27
tags:
  - CTF
categories:
  - 技术
---

之前一直没怎么进一步了解过base64，一直都是会掉模块就行，直到栽了跟头。

## 起因

安洵杯re的“感觉有点简单”中有个base64，除了换表以外，连算法都进行了一定的魔改![question](https://img.0a0.moe/od/01tklsjzdlwx56ku4xgbdlt3ly6kdm7ln3)

第一眼看下去没啥问题，但如果熟悉base64算法的话可以发现中间部分被魔改过

## 基本的base64

根据维基百科所描述的算法![base64_algorithm](https://img.0a0.moe/od/01tklsjzbnwvl3esh7fjbixltnfku4y3ur)

可以写出下面的代码

```python
import base64

table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwzyz0123456789+/"

base_str = "This is a test string."
if len(base_str) % 3 == 1:
    test_str = base_str + "\0\0"
elif len(base_str) % 3 == 2:
    test_str = base_str + "\0"
else:
    test_str = base_str
test_str = [ord(x) for x in test_str]
encoded = []
for i in range(0, len(test_str), 3):
    encoded.append((test_str[i] & 0xfc) >> 2)  # 取第一个字符前六位
    encoded.append(((test_str[i] & 0x03) << 4) | ((test_str[i+1] & 0xf0) >> 4))  # 取第一个字符后两位和第二个字符前四位
    encoded.append(((test_str[i+1] & 0x0f) << 2) | ((test_str[i+2] & 0xc0) >> 6))  # 取第二个字符后四位和第三个字符前两位
    encoded.append(test_str[i+2] & 0x3f)  # 取第三个字符后六位

for i in range(len(encoded)):
    encoded[i] = table[encoded[i]]
if len(base_str) % 3 == 1:
    encoded[-1] = "="
    encoded[-2] = "="
elif len(base_str) % 3 == 2:
    encoded[-1] = "="

print("".join(encoded))
print(base64.b64encode(base_str.encode()).decode())
print("".join(encoded) == base64.b64encode(base_str.encode()).decode())
```

这里我采取了先填充0的方式补足长度，最后再将对应末尾的A改为=

## 回归题目

通过对比Python的实现代码和原题目反编译出的代码，可以发现题目中的代码将顺序上下颠倒过来，导致无法通过base64模块加普通的换表解决这个问题。

为此需要根据原理手写相应的解密算法

```python
str1 = "6zviISn2McHsa4b108v29tbKMtQQXQHA+2+sTYLlg9v2Q2Pq8SP24Uw="

table = "4KBbSzwWClkZ2gsr1qA+Qu0FtxOm6/iVcJHPY9GNp7EaRoDf8UvIjnL5MydTX3eh"

str1 = str1.replace("=", table[0])
data = []
for i in range(0, len(str1), 4):
    data.append((table.find(str1[i])) | ((table.find(str1[i+1]) & 3) << 6))
    data.append(((table.find(str1[i+1]) & 0x3c) >> 2) | ((table.find(str1[i+2]) & 0xf) << 4))
    data.append(((table.find(str1[i+2]) & 0x30) >> 4) | (table.find(str1[i+3]) << 2))
```

即可得到正确结果

## 拓展

其他的base64逆向后伪代码![other_base64](https://img.0a0.moe/od/01tklsjzg2yf3qsk2cj5hkcogkyoq7zhj7)
