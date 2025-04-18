---
title: 2024 网鼎杯决赛 部分题目 Writeup
comments: true
date: 2024-11-26 18:28:47
tags:
  - CTF
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzccwbxq2awmt5dz7pmi3tqn3yan
---

封面：[X@nyancodon7](https://x.com/nyancodon7/status/1860615439602303373)
题目还挺好玩的，就是本人技术有点菜

## 半决赛

### 网络通信流量分析 - socket

题目三个文件：ser和cli还有一段流量

可以看到cli里面就是客户端基础的接收和发送功能，ser里面才有加密和验证。ser监听8888端口的数据，接收password，计算md5后验证比对，然后将password作为RC4的key解密数据输出返回。

刚开始想直接爆md5，忽然想起来还有段流量。查看流量可以直接找到`WangDingCUPKEY!!`

![image-20241126212631576](https://img.0a0.moe/od/01tklsjza4u5i2voebhng2xfjpqmsy3fpd)

然后是返回完right下面的RC4解密，非常标准，注意还有个异或

![屏幕截图 2024-11-23 102203](https://img.0a0.moe/od/01tklsjzfo426oihu3lbez24a3fmasxvqj)

得到flag

这道题其实如果有libcrypto.so.1.1运行库还能做得快一些。回去有网后整了个lib得到password后直接运行ser和cli输入即可得到

![image-20241126212945284](https://img.0a0.moe/od/01tklsjzdtthusd52hfbei4d5paxnmiiru)

### 5G 网络隐私保护 - Get_supi

这类标准的题目做法一般都是看文档慢慢找就能做出来，不过这题看流量就能做出来。翻一下后面的流量就能找到supi的数据

![image-20241126213337136](https://img.0a0.moe/od/01tklsjzgoh2fudurabvazlvi72wvr4ou2)

测试把数字交上去就行

### 安全运营挑战赛-威胁分析-02

> 识别安全防护软件的查杀记录，对于评估系统受感染的程度和了解攻击者所使用的工具至关重要。通过检查安 全日志，可以获取被检测到的威胁信息。 请问，Windows Defender 检测到的第一个恶意软件的威胁ID是什么？（请将答案编辑并存 入/opt/wxfx/answer/2.txt文件中，参考/opt/wxfx/example目录）

这里看硬盘镜像，先使用AccessData FTK Imager提取出所有文件，不要直接挂载，有些文件会看不到。然后到Windows\System32\winevt\Logs下面找Windows Defender的日志文件查看id就行

![image-20241127002251088](https://img.0a0.moe/od/01tklsjza326ecjpbhbnfyipq3eu7mcbqj)

### 安全运营挑战赛-应急响应-07 

> 查明并处理篡改的首页 公司Web业务系统首页遭受黑客攻击，并被植入恶意链接。请您立即进行排查和处理受影响的首页，确保系统的可用性、安全性和完整性

第一次登录时会弹update.exe，查找相关代码，找到`LKT/webapp/_compile/Login/%%45^45E^45E480CD%%index.tpl.php`，然后删掉相关代码就行，只是注释的话过不了check，估计是直接读文件判断关键词

### 安全运营挑战赛-应急响应-08

> 查明并处理植入的后门 公司Web业务系统遭受黑客攻击，并被植入后门。请您立即进行排查和处理，确保系统的安全性和完整性。

D盾扫一下找到`LKT/images/173016881275.php`

![image-20241127004004979](https://img.0a0.moe/od/01tklsjzavsljvypie5zhjajqcjexhy4us)

eval执行，直接把images目录下php全清掉

### 安全运营挑战赛-应急响应-09

> 查明被利用的漏洞 公司Web业务系统遭受黑客攻击，黑客利用漏洞进行攻击并被植入后门。请您立即进行排查黑客利用的漏洞点，确保系统的安全性和完整性。

接着上面的，搜索看看哪里会上传文件到images目录下，找到`LKT/webapp/modules/system/actions/uploadImgAction.class.php`，给里面的

```php
$imgURL=($_FILES['imgFile']['tmp_name']);
$type = str_replace('image/', '.', $_FILES['imgFile']['type']);
$imgURL_name=time().mt_rand(1,1000).$type;
move_uploaded_file($imgURL,$uploadImg.$imgURL_name);
```

中间加一个类型判断，php的直接不允许上传就行

### 安全运营挑战赛-应急响应-10

> 查明泄露的文件 公司Web业务系统遭受黑客攻击，有敏感信息丢失。请您立即进行排查，确保系统的机密性。

排查了半天，发现把backup.zip删掉就行

## 决赛

决赛的题目名没记下来，只记得大概，比赛现场被企业打麻了脑子空白都没做出来，回来就出了

### modbus

[题目附件](https://shamiko-my.sharepoint.com/:u:/g/personal/m_yuru_pro/EZLqLP612vtMmbyO3BBwriIB-FuqGnnGu4fh66WX-l0_Ng?e=ovWNBO)

这题跟上面的第一题类似有个server和client。判断逻辑依旧在server。数据要加密会首先进入一个类似分发器的函数中，会将输入的char取第偶数个的高位来判断将输入传入哪个函数或者是退出。如果是`0?`会进入换表函数，如果是`3?`会进入魔改RC4，如果是`E?`会进入一个异或。

可能是编译时开了优化的原因IDA除了魔改RC4都不能很好反编译这几个函数，尤其是换表函数，需要动调才能得到实际逻辑

反汇编得到的C以及用Python写的实际逻辑

换表：

```c
void __fastcall magic(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 i; // [rsp+18h] [rbp-118h]
  __int64 v3; // [rsp+20h] [rbp-110h]
  __int64 v4; // [rsp+28h] [rbp-108h]
  __int64 v5; // [rsp+30h] [rbp-100h]
  __int64 v6; // [rsp+38h] [rbp-F8h]
  __int64 v7; // [rsp+40h] [rbp-F0h]
  __int64 v8; // [rsp+48h] [rbp-E8h]
  __int64 v9; // [rsp+50h] [rbp-E0h]
  __int64 v10; // [rsp+58h] [rbp-D8h]
  __int64 v11; // [rsp+60h] [rbp-D0h]
  __int64 v12; // [rsp+68h] [rbp-C8h]
  __int64 v13; // [rsp+70h] [rbp-C0h]
  __int64 v14; // [rsp+78h] [rbp-B8h]
  __int64 v15; // [rsp+80h] [rbp-B0h]
  __int64 v16; // [rsp+88h] [rbp-A8h]
  __int64 v17; // [rsp+90h] [rbp-A0h]
  __int64 v18; // [rsp+98h] [rbp-98h]
  __int64 v19; // [rsp+A0h] [rbp-90h]
  __int64 v20; // [rsp+A8h] [rbp-88h]
  __int64 v21; // [rsp+B0h] [rbp-80h]
  __int64 v22; // [rsp+B8h] [rbp-78h]
  __int64 v23; // [rsp+C0h] [rbp-70h]
  __int64 v24; // [rsp+C8h] [rbp-68h]
  __int64 v25; // [rsp+D0h] [rbp-60h]
  __int64 v26; // [rsp+D8h] [rbp-58h]
  __int64 v27; // [rsp+E0h] [rbp-50h]
  __int64 v28; // [rsp+E8h] [rbp-48h]
  __int64 v29; // [rsp+F0h] [rbp-40h]
  __int64 v30; // [rsp+F8h] [rbp-38h]
  __int64 v31; // [rsp+100h] [rbp-30h]
  __int64 v32; // [rsp+108h] [rbp-28h]
  __int64 v33; // [rsp+110h] [rbp-20h]
  __int64 v34; // [rsp+118h] [rbp-18h]
  unsigned __int64 v35; // [rsp+128h] [rbp-8h]
  __int64 savedregs; // [rsp+130h] [rbp+0h] BYREF

  v35 = __readfsqword(0x28u);
  v3 = 0xC56F6BF27B777C63LL;
  v4 = 0x76ABD7FE2B670130LL;
  v5 = 0xF04759FA7DC982CALL;
  v6 = 0xC072A49CAFA2D4ADLL;
  v7 = 0xCCF73F362693FDB7LL;
  v8 = 0x1531D871F1E5A534LL;
  v9 = 0x9A059618C323C704LL;
  v10 = 0x75B227EBE2801207LL;
  v11 = 0xA05A6E1B1A2C8309LL;
  v12 = 0x842FE329B3D63B52LL;
  v13 = 0x5BB1FC20ED00D153LL;
  v14 = 0xCF584C4A39BECB6ALL;
  v15 = 0x85334D43FBAAEFD0LL;
  v16 = 0xA89F3C507F02F945LL;
  v17 = 0xF5389D928F40A351LL;
  v18 = 0xD2F3FF1021DAB6BCLL;
  v19 = 0x1744975FEC130CCDLL;
  v20 = 0x73195D643D7EA7C4LL;
  v21 = 0x88902A22DC4F8160LL;
  v22 = 0xDB0B5EDE14B8EE46LL;
  v23 = 0x5C2406490A3A32E0LL;
  v24 = 0x79E4959162ACD3C2LL;
  v25 = 0xA94ED58D6D37C8E7LL;
  v26 = 0x8AE7A65EAF4566CLL;
  v27 = 0xC6B4A61C2E2578BALL;
  v28 = 0x8A8BBD4B1F74DDE8LL;
  v29 = 0xEF6034866B53E70LL;
  v30 = 0x9E1DC186B9573561LL;
  v31 = 0x948ED9691198F8E1LL;
  v32 = 0xDF2855CEE9871E9BLL;
  v33 = 0x6842E6BF0D89A18CLL;
  v34 = 0x16BB54B00F2D9941LL;
  for ( i = 0LL; i < a2; ++i )
    *(_BYTE *)(a1 + i) = *((_BYTE *)&savedregs + 16 * (*(_BYTE *)(a1 + i) >> 4) + (*(_BYTE *)(a1 + i) & 0xF) - 0x110);
}
```

```python
table = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
         0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
         0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96,
         0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
         0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
         0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
         0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF,
         0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
         0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32,
         0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
         0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
         0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
         0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E,
         0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
         0xB0, 0x54, 0xBB, 0x16]

def change_table(dest, dest_len):
    for i in range(dest_len):
        dest[i] = table[dest[i]]
    return dest
```

魔改RC4：

其实就在最后异或那里加多了个i

异或：

```c
void __fastcall magic_xor(__int64 a1, unsigned __int64 a2)
{
  int v2; // [rsp+1Ch] [rbp-34h]
  unsigned __int64 i; // [rsp+20h] [rbp-30h]
  int v4[6]; // [rsp+30h] [rbp-20h]
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v4[0] = 0x67452301;
  v4[1] = 0x98BADCFE;
  v4[2] = 0x10325476;
  v4[3] = 0x1234567;
  for ( i = 0LL; i < a2; i += 4LL )
  {
    v2 = v4[(i >> 2) % 4] ^ ((*(unsigned __int8 *)(i + 2 + a1) << 8) | (*(unsigned __int8 *)(i + 1 + a1) << 16) | (*(unsigned __int8 *)(a1 + i) << 24) | *(unsigned __int8 *)(i + 3 + a1));
    *(_BYTE *)(a1 + i) = HIBYTE(v2);
    *(_BYTE *)(i + 1 + a1) = BYTE2(v2);
    *(_BYTE *)(i + 2 + a1) = BYTE1(v2);
    *(_BYTE *)(i + 3 + a1) = v2;
  }
}
```

```python
def magic_xor(dest, dest_len):  # e?
    xor_data = [0x67, 0x45, 0x23, 0x01, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x01, 0x23, 0x45, 0x67]
    for i in range(dest_len):
        dest[i] ^= xor_data[i%len(xor_data)]
    return dest
```

反正反汇编出来的很抽象，动调才能知道实际逻辑简化，魔改RC4的key也是动调拿出来比较方便，查引用找不到设置的地方

可以写出相反逻辑，然后直接爆破比较方便。原本想根据前面分发器的逻辑去逆向的，但是太麻烦了，不如直接递归去爆方便

```python
table = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
         0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
         0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96,
         0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
         0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
         0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
         0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF,
         0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
         0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32,
         0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
         0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
         0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
         0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E,
         0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
         0xB0, 0x54, 0xBB, 0x16]

def change_table(dest, dest_len):
    for i in range(dest_len):
        dest[i] = table[dest[i]]
    return dest

def change_table_reverse(dest, dest_len):  # 0?
    for i in range(dest_len):
        dest[i] = table.index(dest[i])
    return dest

key = [0x77, 0x65, 0x6C, 0x63, 0x6F, 0x6D, 0x65, 0x6D, 0x79, 0x6D, 0x6F, 0x64, 0x62, 0x75, 0x73, 0x21]

def not_RC4(dest, dest_len):  # 3?
    S = [i for i in range(256)]
    v1 = 0
    for j in range(256):
        v1 = (S[j] + v1 + key[j%16] + j) & 0xff
        v2 = S[j]
        S[j] = S[v1]
        S[v1] = v2
    v10 = 0
    v11 = 0
    for k in range(dest_len):
        v10 = v10 + 1
        v11 = (S[v10] + v11) & 0xff
        v4 = S[v10]
        S[v10] = S[v11]
        S[v11] = v4
        dest[k] ^= S[(S[v11] + S[v10] + v10)&0xff]
    return dest

def magic_xor(dest, dest_len):  # e?
    xor_data = [0x67, 0x45, 0x23, 0x01, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x01, 0x23, 0x45, 0x67]
    for i in range(dest_len):
        dest[i] ^= xor_data[i%len(xor_data)]
    return dest

def check_is_all_printable(dest, dest_len):
    for i in range(dest_len):
        if dest[i] < 0x20 or dest[i] > 0x7e:
            return False
    print(dest)
    print(''.join([chr(i) for i in dest]))
    return True

def traverse(dest, dest_len, depth):
    if depth == 0:
        if check_is_all_printable(dest, dest_len):
            return True
        return False
    dest_tmp = dest.copy()
    dest_tmp = change_table_reverse(dest_tmp, dest_len)
    if traverse(dest_tmp, dest_len, depth-1):
        return True
    dest_tmp = dest.copy()
    dest_tmp = not_RC4(dest_tmp, dest_len)
    if traverse(dest_tmp, dest_len, depth-1):
        return True
    dest_tmp = dest.copy()
    dest_tmp = magic_xor(dest_tmp, dest_len)
    if traverse(dest_tmp, dest_len, depth-1):
        return True
    return False

if __name__ == '__main__':
    dest = [0xDB, 0x3A, 0x48, 0xC7, 0x60, 0xB1, 0x1C, 0x01, 0xB0, 0xCE, 0xE8, 0x3A, 0x7E, 0x6D, 0x93, 0x3C, 0x9C, 0xCE, 0x08, 0xA3, 0x50, 0x45, 0xFD, 0xC0, 0x45, 0xC7, 0xE8, 0xC9, 0xC9, 0x80, 0xDB, 0x6C]
    length = 32
    for i in range(1, 17):
        if traverse(dest, length, i):
            break
# 35e887ec0a49d315f0bb96da9146a90e
```

![屏幕截图 2024-11-26 002941](https://img.0a0.moe/od/01tklsjzbf5mkrua4goffiolzxwoibrhbf)

### financeapk

[题目附件](https://shamiko-my.sharepoint.com/:u:/g/personal/m_yuru_pro/ET3HYbU06cZHmMBk6IdFHrwBlXYMcVaNtaMMZ6OsP-661Q?e=idvO7n)

应该是去逆登录请求的加密逻辑，但逆出来后感觉有些怪，不确定后面还有没有内容

根据流量找到调用的setLoginPost这个native函数，可以看到里面先有一个魔改XXTEA加密然后是b64encode，先解base64然后再逆XXTEA。key可以通过frida hook XXTEA加密函数得到

![image-20241126234912813](https://img.0a0.moe/od/01tklsjzfr2copblqbcjdk23l5axutbxnm)

或者查看逻辑，由

```java
String a = getLocalClassName().toString();
String b = getComponentName().getShortClassName().toString();
String c = getPackageName().toString();
System.out.println(a);
System.out.println(b);
System.out.println(c);
getKeyJNI(a, b, c);
```

调用`getKeyJNI`得到。里面是拼接字符串取MD5字符串前16位作为key。因此可以根据反编译代码写出解密代码

```python
from ctypes import *
encode = [0x90,0xe2,0xf1,0x44,0x94,0xa1,0xf8,0xdb,0x5e,0xfb,0x3a,0x68,0xf9,0xb4,0xbe,0x61,0x69,0x8c,0x1d,0x47,0x89,0x0f,0x56,0xd2,0x63,0x4c,0x53,0x4f,0xf4,0xbf,0x74,0x68,0x71,0x8e,0x89,0xa8,0xaf,0x57,0x46,0xbc,0x2e,0xb2,0xdb,0xcf,0xe5,0x94,0x08,0x2e,0xc4,0xee,0xaf,0x41,0x8a,0x41,0x42,0x0d,0x38,0x7f,0x38,0xe9,0xf4,0x27,0xcb,0x1c,0x1c,0x5a,0xd3,0xe2,0xde,0xc1,0xe5,0x31,0xe3,0x51,0x7d,0x64,0x82,0x08,0xb3,0x20,0x96,0x2f,0xee,0x4a,0x4a,0xcb,0xf0,0x04,0x76,0x44,0x32,0x3e,0x48,0xcc,0x67,0xdc,0x62,0x7f,0x3b,0xab,0x1d,0x7c,0x99,0xcf,0x2a,0xd2,0xc3,0xc5,0xb6,0x86,0x9a,0x93,0x84,0x51,0xe2,0xd1,0xa2,0xa6,0x4b,0xfe,0xf4,0x21,0x8e,0x73,0xa7,0x6f,0x45,0xa7,0x88,0xde,0x67,0x51,0xfa,0xd9,0x55,0xb6,0x63,0x1b,0xa4,0x02,0x4c,0x3e,0x00,0xa7,0xfc,0x4d,0x42,0x35,0x18,0x2a,0x5e,0x58,0x5d,0x7a,0x6d,0x21,0x55,0xa4,0x54,0xe0,0x77,0xb3,0xce,0xe4,0x4c,0xce,0x1a,0x28,0xe7,0xf9,0x64,0x60,0xa5,0xed,0x2c,0xc8,0xfd,0x94,0x24,0xdf,0x44,0x45,0x3a,0xb8,0x95,0x9a,0x0c,0xab,0x52,0x3f,0x5c,0x0c,0xbe,0xae,0xbf,0x6b,0x62,0x46,0x45,0x23,0x9f,0x63,0x70,0x94,0xb7,0xdd,0x46,0xf7,0x06,0xb9,0x7b,0xd5,0x6c,0x04,0xe4,0xf4,0x47,0x73,0x07,0x09,0x75,0x17,0xfc,0x13,0x93,0xac,0x8a,0x6d,0x61,0xbf,0x0f,0x0a,0x07,0xc9,0x7f,0x0b,0xcc,0xf2,0x97,0xa6,0x25,0x8d,0x02,0x40,0xb0,0xdb,0x51,0x34,0x70,0x32,0x67,0xd5,0xf4,0xe6,0xe4,0x95,0xf9,0xe6,0x1a,0xc0,0xbd,0xb2,0x8a,0x30,0xd9,0x78,0x95,0x59,0x30,0xf7,0x0f,0x97,0x4e,0x99,0x32,0x76,0x5e,0xc3,0x12,0x3b,0x53,0x4b,0x4f,0x7b,0xee,0x5d,0xf9,0x5d,0x4d,0xae,0x31,0xfc,0xe3,0x74,0x3e,0xcf,0x46,0x3a,0x6a,0x31,0x99,0xec,0xac,0xe5,0xf8,0xa0,0x6c,0xe2,0xdf,0x4f,0x69,0xff,0xeb,0xeb,0x25,0x16,0x38,0xf2,0x58,0x86,0x84,0xe8,0x6a,0xc5,0x0b,0x30,0xd4,0xd2,0x14,0xe9,0xfa,0x95,0x20,0x30,0x0d,0x5a,0xe4,0x3a,0x95,0x60,0xbf,0x57,0x7e,0x31,0x98,0xa1,0x71,0xa2,0x2b,0x28,0x40,0x2b,0xe2,0x3e,0x80,0x89,0x7a,0x5e,0x3f,0xf2,0x67,0x79,0x97,0x67,0x8f,0x07,0xf8,0xe0,0x4c,0x51,0xfa,0x72,0x59,0xc5,0xb9,0x73,0x97,0xf1,0x3e,0x29,0x35,0xd1,0x31,0x66,0x4f,0x1b,0x20,0xc1,0xeb,0x5a,0x99,0x0b,0x62,0x10,0x3e,0x98,0xa5,0xfb,0xaf,0xce,0x4b,0xde,0x07,0x23,0x17,0xf0,0x88,0x1d,0x95,0xe1,0x07,0x9e,0xf0,0xee,0xf6,0xff,0xf4,0x9c,0x5b,0x6e,0x36,0xf6,0xd5,0xef,0x61,0xb6,0x16,0xb9,0x85,0x44,0xd4,0x25,0xf2,0x88,0x34,0x51,0x88,0xf0,0xf8,0x90,0xab,0x83,0xb6,0xc8,0x21,0xf1,0xb7,0x25,0xfc,0x15,0xee,0xd3,0x70,0x23,0xbb,0x05,0xba,0x6d,0x0d,0x4b,0x35,0x2b,0xf1,0xb6,0x33,0x65,0x5e,0x58,0x5b,0x64,0xd4,0x19,0x73,0x36,0xec,0x22,0x36,0x7e,0x9c,0xf1,0xe1,0xc2,0x80,0xfe,0x63,0xd8,0x99,0x25,0x63,0x49,0xa0,0xf0,0xe1,0xce,0xdf,0xfe,0x9a,0xe7,0x88,0x7f,0x38,0x3f,0xbc,0x11,0xc8,0xec,0x83,0xd0,0xbe,0x6c,0x5b,0xfc,0xcf,0x3c,0x5d,0x1a,0xa9,0xa1,0xe7,0x78,0x53,0xd4,0xc3,0xe9,0x31,0x74,0x8c,0xdb,0xe1,0x72,0x7c,0x4f,0x35,0x95,0x56,0xf5,0x7e,0x9a,0x0d,0xb3,0x35,0x9d,0x6d,0xab,0xea,0x66,0x41,0x70,0x22,0x6a,0xb7,0x33,0x40,0xf7,0x8d,0x1c,0x05,0x1c,0xce,0xd9,0x94,0x68,0x9e,0x7e,0x26,0x8e,0x86,0xaa,0x0f,0x20,0x7f,0xc1,0x22,0x14,0x74,0xd0,0x1c,0x15,0x92,0x75,0x42,0x7a,0xc9,0x12,0x53,0x22,0x36,0x8b,0x6a,0x93,0x22,0xdb,0x13,0x83,0x46,0x31,0x93,0x69,0x0e,0x09,0xe7,0xd3,0x42,0x21,0x5b,0xe2,0xeb,0x3b,0x28,0x05,0x1e,0xf2,0xaa,0x5f,0xc6,0x09,0xb2,0x8f,0x64,0x6b,0x10,0x4a,0x51,0x80,0x3c,0x44,0x96,0x72,0x9a,0x41,0xd7,0x3d,0x46,0xcb,0xed,0x54,0xcf,0x04,0x1b,0x2b,0x4b,0x58,0x3b,0xb1,0x10,0x02,0x18,0x65,0x1e,0x1f,0xb8,0x75,0x02,0xca,0x53,0x06,0x5d,0x0c,0xbc,0x76,0xa2,0x9f,0x3d,0x57,0x5c,0xe6,0xb3,0x0e,0xfa,0xe9,0xe7,0x82,0x30,0x26,0xae,0x5c,0x2b,0x92,0x18,0xd0,0x43,0x4d,0x21,0xf1,0xce,0x55,0x6c,0x98,0x29,0x4a,0xf6,0xc4,0x1f,0x9b,0x73,0x1e,0xa8,0x75,0x3e,0xc3,0x9c,0xe0,0x7d,0x6a,0xb5,0x81,0x05,0x43,0x6b,0xc0,0xe5,0xb5,0xcf,0x27,0xf6,0x59,0xc0,0x58,0x84,0xf0,0xe9,0x6a,0x83,0xa2,0x1a,0x3d,0x25,0x7e,0x43,0xa4,0x8d,0x93,0xb0,0xb4,0x01,0x90,0xdc,0xc3,0xaa,0x9c,0x1c,0x4d,0x72,0x0c,0x13,0x6b,0x98,0x77,0xe7,0xa4,0x52,0x79,0x8f,0x2a,0x6d,0x79,0x02,0xc4,0x99,0xb9]
encode2 = [0x52,0x45,0x4c,0x70,0xda,0x43,0x2d,0x67,0xd6,0x02,0x4e,0x0d,0x32,0x70,0x75,0xcc,0x1f,0xa2,0xde,0x71,0x97,0x05,0x86,0x01,0xd1,0xa6,0xb1,0x60,0x66,0xaf,0x95,0xe2,0x70,0xd8,0x70,0xce,0x1d,0xd4,0x79,0x9a,0x6e,0xc0,0x23,0xf2,0xe0,0xdb,0xe7,0x05,0xc8,0xaa,0x7a,0xd8,0x16,0x87,0x95,0xf5,0x05,0xf8,0xd2,0x21,0x61,0xe2,0x99,0x38,0x33,0xd8,0x3d,0xc6,0x54,0x04,0x46,0xf1,0x86,0xa2,0xe6,0x8b,0x15,0x0b,0x26,0xe8,0xd1,0x01,0x89,0xf7,0xf5,0x71,0x23,0x41,0x08,0x10,0x10,0x86,0x0d,0x2b,0x3a,0x68,0xcc,0xe4,0xbb,0x87,0x49,0xa5,0x17,0xa8,0x12,0x4a,0xa9,0x16,0x0f,0x01,0x3a,0x05,0x62,0xed,0xc7,0x55,0xa5,0x37,0x17,0x31,0xdf,0x9c,0x2b,0x6e,0xed,0xfe,0x7c,0x6d,0x91,0x3a,0x18,0xf5,0x2e,0x7e,0xd4,0x81,0xb3,0xcb,0xe0,0xfe,0xed,0x43,0x88,0x3a,0x0e,0x29,0xf1,0x0d,0x65,0x38,0xeb,0x87,0xd0,0x8a,0xc5,0x0d,0x1e,0x83,0x80,0xda,0x3e,0xcf,0xec,0x11,0xc6,0xe7,0x2a,0x83,0x37,0x08,0x21,0x0f,0x86,0x63,0x16,0x4d,0xb3,0x53,0x50,0x7a,0xf3,0x48,0x20,0x7b,0xf3,0x2f,0x9a,0x77,0xaa,0x00,0xd2,0x50,0x60,0x9c,0x65,0x6a,0x37,0x28,0x70,0x57,0xb9,0xc9,0x12,0x6e,0x8a,0xc5,0x08,0x40,0x90,0xe1,0xbf,0x52,0x3b,0x06,0xa9,0x6c,0x5d,0x02,0xd7,0x3a,0xb1,0x9b,0x42,0x9a,0xde,0x7d,0x1d,0x58,0xa6,0x18,0xa9,0x74,0xab,0x96,0x89,0xa3,0x6d,0x8f,0xa4,0x93,0x12,0x67,0xd0,0xb5,0xff,0x21,0x8a,0x69,0xca,0x40,0xca,0x78,0x4f,0x57,0x26,0xd7,0x95,0x80,0x50,0xc2,0x7f,0xad,0x23,0x2f,0xab,0x7b,0xc8,0xda,0x5d,0xc6,0x77,0xb7,0xc2,0x6f,0xbd,0x7f,0xe3,0xd2,0x37,0xe9,0x67,0xde,0x42,0x40,0xf6,0x73,0xff,0xb5,0x81,0x2a,0x07,0x98,0xbf,0x7f,0xbf,0x15,0x28,0xcb,0xf9,0xc7,0xe7,0x0e,0x70,0xc5,0x4b,0x42,0x20,0x06,0x1c,0x14,0x1c,0x77,0xe3,0x5d,0x8b,0x12,0x22,0x4b,0xda,0xbe,0xd0,0x99,0x87,0x76,0x1f,0xce,0x57,0xf9,0x11,0x12,0xb3,0xd3,0xcb,0x4f,0xd9,0x0c]

def bytes_to_dwords(byte_list):
    return [(byte_list[i] | (byte_list[i+1] << 8) | (byte_list[i+2] << 16) | (byte_list[i+3] << 24)) for i in range(0, len(byte_list), 4)]

def dwords_to_bytes(dword_list):
    return [byte & 0xff for dword in dword_list for byte in (dword, dword >> 8, dword >> 16, dword >> 24)]

def xxtea_encrypt(data, length, key):
    data = bytes_to_dwords(data)
    last = c_uint32(data[length-1])
    rounds = 0x34 // length + 6
    delta_sum = c_uint32(0)
    while rounds > 0:
        delta_sum.value -= 0x61c8864f
        key_index = (delta_sum.value >> 2) & 3
        for i in range(length-1):
            next_data = c_uint32(data[i+1])
            temp = c_uint32()
            temp.value = data[i] + (((last.value ^ key[key_index ^ i & 3]) + (next_data.value ^ delta_sum.value)) ^ (((16 * last.value) ^ (next_data.value >> 3)) + ((4 * next_data.value) ^ last.value >> 6)))
            data[i] = temp.value
            last = temp
        temp = c_uint32()
        temp.value = data[length-1] + (((last.value ^ key[key_index ^ (length-1) & 3]) + (data[0] ^ delta_sum.value)) ^ (((16 * last.value) ^ (data[0] >> 3)) + ((4 * data[0]) ^ last.value >> 6)))
        data[length-1] = temp.value
        last = temp
        rounds -= 1
    return data

def xxtea_decrypt(data, length, key):
    data = bytes_to_dwords(data)
    rounds = 0x34 // length + 6
    delta_sum = c_uint32(0 - rounds * 0x61c8864f)
    while rounds > 0:
        key_index = (delta_sum.value >> 2) & 3
        for i in range(length-1, 0, -1):
            prev_data = c_uint32(data[i-1])
            temp = c_uint32()
            temp.value = data[i] - (((prev_data.value ^ key[key_index ^ i & 3]) + (data[(i+1) % length] ^ delta_sum.value)) ^ (((16 * prev_data.value) ^ (data[(i+1) % length] >> 3)) + ((4 * data[(i+1) % length]) ^ prev_data.value >> 6)))
            data[i] = temp.value
        temp = c_uint32()
        temp.value = data[0] - (((data[length-1] ^ key[key_index ^ 0 & 3]) + (data[1] ^ delta_sum.value)) ^ (((16 * data[length-1]) ^ (data[1] >> 3)) + ((4 * data[1]) ^ data[length-1] >> 6)))
        data[0] = temp.value
        delta_sum.value += 0x61c8864f
        rounds -= 1
    return data

if __name__ == '__main__':
    key = [0x64,0x36,0x63,0x39,0x30,0x32,0x63,0x36,0x65,0x33,0x66,0x63,0x35,0x66,0x32,0x62]
    decrypted = xxtea_decrypt(encode, len(encode)//4, bytes_to_dwords(key))
    # decrypted = xxtea_decrypt(encode2, len(encode2)//4, bytes_to_dwords(key))
    for i in dwords_to_bytes(decrypted):
        print(chr(i), end='')
    print()
    # for i in dwords_to_bytes(decrypted):
    #     print(hex(i), end=',')
```

然后得到的是一个POST请求内容

```http
POST /login HTTP/1.1
Content-Type: text/plain; charset=utf-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
Host: finance.example.com
Connection: keep-alive
Cookie: rememberMe=F7/W9YymRDa77Pn0XIVt//C+uZ8HOeHM/otoLvCPrV/BJ6Uzo48zGKgiPGd77Cq9rcYZOUDGuUjiQoJG6+sx5MV+rDyZb4fvdR0xOsHTtN6XbeqqF3xr+6fIx3//ALRv0pJg8a6KlqsWOQA4zLBIpMPcKt/+y3H/m/noPADDQVk+QM2KeKVDiPFITaWQB8UEOfQkN0dOdjap1SevKWPMYA5LM3GTkVJqGBuievr2glRTJsoBOFDc+M5IA/aXZIYQQw1WZH9PMFZQVn3vFAiTVV0YRkx2K02PnfbycbSUWwoSzGBnhqKXeN2URswGvKMGOfCzZdwQG3KEt+0D2jx4W3v1iV+bxFEHhe/G5x20E/59tNOk3TL6W5cZnurDZX3g8UZUtRjpgpxilyFs7+VhOkoZJPeST+oEZr+PHqbWGeQ=
Accept-Encoding: gzip, deflate, br

username=admin&password=admin1234ô  
```

~~然后就不知道了，感觉Cookie这里还有操作空间？但没找到相关代码，也没得提交验证~~

经zeropeach提醒，拿去解一下Shiro rememberMe就行了

![image-20241128232555325](https://img.0a0.moe/od/01tklsjza2ke7fzrdrjzdlwt7noynovlhr)
