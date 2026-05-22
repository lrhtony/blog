---
title: 第十八届全国大学生信息安全竞赛（CISCN）暨第二届“长城杯”铁人三项赛 部分Writeup
comments: true
date: 2024-12-17 21:47:44
tags:
  - CTF
categories:
  - 技术
---

Misc好玩嘿嘿，逆向真不熟（

## 逆向工程

### ezCsky

使用Cutter查看汇编，可以得到

![image-20260522222256366](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/bcecea996545b94db468a0527340dc014fdf4b54b295f661038e723b08d63d84.webp)

根据符号名猜测，对data区0x8AA0的42bytes数据使用testkey作为key进行RC4解密，得到数据。通过观测解密后的数据，发现末尾出现}，经过汇编代码及反复测试，发现异或后一位数据即可还原flag

```Python
a = [0x0a,0x0d,0x06,0x1c,0x1f,0x54,0x56,0x53,0x57,0x51,0x00,0x03,0x1d,0x14,0x58,0x56,0x03,0x19,0x1c,0x00,0x54,0x03,0x4b,0x14,0x58,0x07,0x02,0x49,0x4c,0x02,0x07,0x01,0x51,0x0c,0x08,0x00,0x01,0x00,0x03,0x00,0x4f,0x7d]

for i in range(len(a)-2, -1, -1):
    a[i] = a[i] ^ a[i+1]

print(''.join([chr(x) for x in a]))
# flag{d0f5b330-9a74-11ef-9afd-acde48001122}
```

### Dump

ida观察发现程序运行需要传入字符串，然后输出对应长度的hex加密后字符串。通过fuzz发现每位的字符不会影响到其他字符的状态，故可以逐位爆破，此处flag长度较短，因此采用了手动爆破

![image-20260522222312250](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/87b91fec89d2186239d49a7e17c1de24edf913334ecbe054e2cee8de9b2e865b.webp)

### rand0m

### cython

两道cpython再研究一下

## 威胁检测与网络流量分析

### zeroshell_1

排查http流量，发现

![image-20260522222326055](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/7f9ef129a99bb2eb73f00a33ba2bfb9f36e53c60dc7a56e36d45fd36a7649831.webp)

对Referer解base64得flag{6C2E38DA-D8E4-8D84-4A4F-E2ABD07A1F3A}

### zeroshell_2

对虚拟机磁盘文件使用FTK Imager进行提取，打开flag文件即可得

### zeroshell_3

对.nginx可疑隐藏文件分析，发现

![image-20260522222342361](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/de9a7476cb58ae747db75b4e9e4a605e96940d3c7126bca7af81bdb5913887ee.webp)

提交ip

### zeroshell_4

即上面的.nginx

### zeroshell_5

![image-20260522222357247](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/90003ce8b587d06dcb0f4fb34ccfd48c09108a46281d161c2ca8af0c7a5c0917.webp)

在刚刚ip下面可发现字符串，查找引用即可确定为密钥

### zeroshell_6

使用vscode对/var/register/system文件夹下搜索恶意文件名，找到

![image-20260522222410541](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/422e540199a26832738a6ba99e79513c63a11f008b377ff50fb2c41ae7fa8656.webp)

即/var/register/system/startup/scripts/nat/File

### WinFT_1

使用CurrPorts发现外联

![image-20260522222423372](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/b2f066768e913c6a019dda04252bc457a02d9c2323d5caf65a22418805e3a4dd.webp)

看不到域名，查找hosts文件

![image-20260522222435468](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/9ddcbd58955a53d46ac2eb35d5baa43deba61078b8cbf0205e2a787500f80315.webp)

miscsecure.com:192.168.116.130:443

### WinFT_2

计算机管理计划任务里面发现flag

![image-20260522222447249](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/1556fde8cb5a0b1117fee52f2788d4bb0e5372e9cbb273f9e995c531a97d5d9c.webp)

![image-20260522222505791](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/fe70268b527600eb3acf8e522d990036abc74395244cc0644813e028ad53f8af.webp)

### WinFT_5（赛后出）

筛选http请求，发现client里面出现压缩包，但没东西。然后下面的server发现flag.txt

![image-20241218021610285](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/7286d4c909f347a84fa78e81df463702315f8512127262864514574064d9a3e6.webp)

![image-20241218021727032](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/fb99c15a7cc33045d672bad8ff9e634669c99a6e031e2453b058573adb5331cf.webp)

提取出来，使用7zip打开绕过完整性报错，末尾注释解base64得到`时间线关联非常重要`，作为压缩文件密码解密即可得到`flag{a1b2c3d4e5f67890abcdef1234567890-2f4d90a1b7c8e2349d3f56e0a9b01b8a-CBC}`

### sc05_1

综合firewall几个表，在tcp-export中发现最早外联时间为 2024/11/09 16:22:42 

![image-20260522222542355](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/f94883a02989575a4a03eef54d332e9865e030d9a0767f489d7589c4f1305b2c.webp)

### Kiwi

对Kiwi进行逆向

![image-20260522222557335](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/cca8a2da8398c82f61026877cd9f9b03ce12b19e9e22d610849c1a122397ef90.webp)

可以发现前面通过lsadump获取密钥，然后通过sub_140082974对数据加密，最后通过sub_140082774发送http://421aa90e079fa326b6494f812ad13e79.com/upload

加密部分为换表base64+随机数

![image-20260522222609881](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/2256aa0482991eee08234ba48440428751dd4534ce2905307adfa94968ee5896.webp)

![image-20260522222621148](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/3804bfed29c670987e58eb1a6077be123f3943f5e169e12c0eb2f687002d231a.webp)

```C
#include <stdio.h>
#include <stdlib.h>

char data[] = {0xb9,0x48,0x1c,0x58,0x81,0x4f,0x51,0x7d,0x27,0x70,0x33,0x6f,0x79,0x48,0x82,0x21,0x08,0x80,0x79,0x49,0x51,0x52,0x28,0x9b,0x7d,0xbb,0x40,0x67,0x45,0x7a,0x96,0x38,0x3e,0x7d,0x41,0x42,0x86,0x60,0x4f,0x6c,0x3b,0x87,0x2e,0x26,0x72,0x51,0x83,0x80,0x79,0xbd,0x79,0x40,0x67,0x71,0x4a,0xa2,0x98,0x76,0x3a,0x8f,0x68,0xda,0x7f,0x74,0x2a,0x33,0x55,0x8d,0x5e,0x2b,0x39,0x6d,0xbe,0x5f,0x74,0x74,0x7d,0x11,0x8e,0x4b,0x4d,0x99,0x64,0x79,0x63,0xb3,0x73,0xca,0x31,0x90,0xc3,0x77,0x1b,0x6f,0x61,0x52,0x11,0xbc,0xbd,0x86,0xb2,0x78,0x4f,0x7e,0x56,0x8f,0x6c,0x94,0xb4,0x3a,0x7f,0x14,0x4b,0x79,0xb6,0x8c,0xb0,0xad,0x8b,0x67,0x6d,0xd1,0x7a,0x9a,0xa7,0x31,0x74,0x25,0x3e,0x61,0x2e,0x82,0x3d,0x63,0x5e,0x77,0x6b,0x7c,0x3f,0x24,0x65,0x35,0x9f,0x53,0x84,0x92,0x42,0xa0,0x7d,0x66,0x70,0x3b,0xd3,0x65,0xa2,0x6d,0x7f,0x19,0x92,0x7a,0x8c,0xb8,0x6b,0x12,0x18,0x66,0x74,0xc0,0x48,0x64,0x9d,0x0e,0x6f,0x53,0x96,0x49,0x61,0x5d};

int main()
{
    // char seed_key[] = "FixedSeed";
    // int v5, v6 = 0, v8 = 1, v7=0;
    // do {
    //     v5 = seed_key[v7++];
    //     v6 = (v6 + v8 * v5) % 256;
    //     ++v8;
    // } while (v5);
    // printf("%d\n", v6);
    int v6 = 105;
    srand(v6);
    for (int i = 0; i < sizeof(data); i++) {
        printf("%c", (data[i] - (rand()%128))^v6);
    }
    return 0;
}
// User=Administrator
// NTLM=
// User=DefaultAccount
// NTLM=
// User=Guest
// NTLM=
// User=Lihua
// NTLM=23d1e086b85cc18587bbc8c33adefe07
// User=WDAGUtilityAccount
// NTLM=d3280b38985c05214dcc81b74dd98b4f
```

使用hashcat爆破NTLM

![image-20260522222635366](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/eea01a49f25b6c9a303ff273c19413cb83090642f68b33ac9983e9f329a5cee3.webp)

### sxmisc (赛后出)

sql盲注日志和流量

注意到每次盲注后面注释有4个随机字符，可以拿来分组，写脚本

```python
import re
import json
from urllib.parse import unquote

# 解析access.log
with open('access.log', 'r', encoding='utf-8') as f:
    lines = f.readlines()

pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)\s'   # IP地址和端口
    r'(?P<client_ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s'   # 客户端IP
    r'\[(?P<timestamp>.*?)\]\s'                    # 时间戳
    r'"(?P<method>\w+)\s(?P<path>[^\s]+)\sHTTP/1.1"\s'  # 请求方法和path
    r'(?P<status>\d+)\s(?P<size>\d+)\s'            # 状态码和返回字节数
    r'"(?P<referrer>.*?)"\s'                       # 来源链接
    r'"(?P<user_agent>.*?)"'                       # 用户代理
)

logs = []
for line in lines:
    match = pattern.match(line)
    if match:
        log = match.groupdict()
        log['size'] = int(log['size'])
        log['status'] = int(log['status'])
        log['path'] = unquote(log['path'])
        logs.append(log)

print('[+] 共解析出%d条日志' % len(logs))

# 筛选出user-agent为sqlmap/1.8.9.1#dev (https://sqlmap.org)，且时间在01/Nov/2024:03:07:32 +0000及之后的请求，且path开头为"/publishers.php?pub_id=9952",末尾为"-- 任意四字符"
filter_log = []
for log in logs:
    if log['user_agent'] == 'sqlmap/1.8.9.1#dev (https://sqlmap.org)' and log['timestamp'] >= '01/Nov/2024:03:07:32 +0000':
        pattern = re.compile(r'-- [a-zA-Z]{4}')
        if pattern.match(log['path'][-7:]) and log['path'].startswith('/publishers.php?'):
            filter_log.append(log)

print('[+] 共筛选出%d条日志' % len(filter_log))


# 将log根据特征进行分组
grouped_logs = {}
for log in filter_log:
    key = log['path'][-4:]
    if key not in grouped_logs:
        grouped_logs[key] = []
    grouped_logs[key].append(log)

print('[+] 共分组%d组' % len(grouped_logs))

grouped = {}
for key, logs in grouped_logs.items():
    pattern = r"SUBSTR\(\((.*?)\),(\d+),\d+\)([>=])CHAR\((\d+)\)"
    if len(logs) > 1:
        for log in logs:
            match = re.search(pattern, log['path'])
            if match:
                if key not in grouped:
                    grouped[key] = {'sql': match.group(1), 'chars': []}
                pos = int(match.group(2))
                if pos > len(grouped[key]['chars']):
                    grouped[key]['chars'].append([])
                grouped[key]['chars'][pos-1].append((match.group(3), int(match.group(4)), log['size'] == 459))


for key, value in grouped.items():
    result_str = ''
    print(value['sql'])
    for i, chars in enumerate(value['chars']):
        larger = []
        smaller_equal = []
        skip = False
        for char in chars:
            if char[0] == '=' and char[2]:
                result_str += chr(char[1])
                skip = True
                break
            if char[0] == '>' and char[2]:
                larger.append(char[1])
            else:
                smaller_equal.append(char[1])
        if not skip:
            if len(smaller_equal) > 0:
                result_str += chr(min(smaller_equal))
            else:
                result_str += chr(max(larger))
    print(result_str)
    print()
```

得到注入及返回。搜索发现

```sql
SELECT COALESCE(CAST(pr_info AS TEXT),CHAR(32)) FROM pub_info LIMIT 6,1
This is sample text data for Scootney Books, publisher 9952 in the pubs database. Scootney Books is located in New York City, New York.you may view the updated logo if you want to get you flag.
```

查找update流量，发现有/update_pubinfoform.php和/updatepubinfo.php。前一个没东西，后面有一个JPEG

![dump1](https://img.0a0.moe/blog/2024/12/17/%E7%AC%AC%E5%8D%81%E5%85%AB%E5%B1%8A%E5%85%A8%E5%9B%BD%E5%A4%A7%E5%AD%A6%E7%94%9F%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B-ciscn-%E6%9A%A8%E7%AC%AC%E4%BA%8C%E5%B1%8A%E9%95%BF%E5%9F%8E%E6%9D%AF%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9%E8%B5%9B-%E9%83%A8%E5%88%86writeup/b44d91c5daa5e65208bae1fa9fed30013f2a07fcfdf3eecc0e9f8a801847c4f1.webp)

找到Pontes这个用户盲注出来的数据

```sql
SELECT COALESCE(CAST(acc_flag AS TEXT),CHAR(32)) FROM accounts LIMIT 7,1
tJkjkC9zdTfV/vjWjKBQERPvbJB+MTzNgv9Q7OsSeW9VO+cz9GM7gdfFu3+UwSfK
p3OStBv6wESZitD8x9rR8Jx4LwKU+i1ysKUQWOvORYSSif1zt37ored1r1IALNX1
jKEWRMZXTQU07kNULKk3Zve7Q8qTnbGviNqFjG3W4s0=


SELECT COALESCE(CAST(acc_id AS TEXT),CHAR(32)) FROM accounts LIMIT 7,1
94

SELECT COALESCE(CAST(acc_name AS TEXT),CHAR(32)) FROM accounts LIMIT 7,1
Pontes

SELECT COALESCE(CAST(acc_pwd AS TEXT),CHAR(32)) FROM accounts LIMIT 7,1
Pontes

SELECT COALESCE(CAST(acc_type AS TEXT),CHAR(32)) FROM accounts LIMIT 7,1
user

SELECT COALESCE(CAST(create_date AS TEXT),CHAR(32)) FROM accounts LIMIT 7,1
2024-11-01

SELECT COALESCE(CAST(emp_id AS TEXT),CHAR(32)) FROM accounts LIMIT 7,1
MJP25939M

SELECT COALESCE(CAST(priv_key AS TEXT),CHAR(32)) FROM accounts LIMIT 7,1
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIOsDeLUSmUYYCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBC90/rdH5nC9mPbmu8wyVI4BIIC
gLK3anRAfdD6+mm5zQu6GssbXAkDka9BZw5Q7fvz+Dsjp4f2SHBv0l2yXzOV0WES
qCz6xiwwJ1pRZ81F+ITcypFZl09mctZ79RHVySW0Khy5qS7LmMK0VegttpdXqz31
otPcqC2l5zrVurtiRCHwWmVBPKBmlcCCLCLkRugTga33QDt63OKE7J21rbzWxtZR
5tHzvrbA80sPVplstF25fA2LmF53XAi4I1b06Okb2gtmIVu8Sf8MTmlpHZ5zel5l
Lpt4G7XvUtd+icZWKrhGfTC3mBneeD1hkDGxhf/KksIeCUTb8tlwPxiASJ9HjPw2
64+Ipmqb3JkvFQLRC4CdhSluSvlEuCo4vvHu/aUhvuRe40LuaI2uc2v+2xJahl3Z
cbR7b0WUm4V+fnbB9YioaDrQ8qJtpfEAMCsDKu4Dql+8kZOps64xMyek/8DIE1Hf
Xp0RHD15qTemAnnsy/LI5X70O6mhvh8I6MU7M5dYfuIb9ytStNfrOmfE6QEK+biw
7xJE8AzK4pLLIpojLsIqh68l4ZnJnSC4hb14ashKk9Wr0MR9Zize3gLSGeBbB+w9
fkXivQuZAT4d7An+/19D4Q/I1kNZTipdWxCJWMHnBJVzlE6JrTZg1RrtIbXUxaxw
rD6AiW5fK6fAFzwM12x5/w53T/CH4qMtjtreM5SNvrJ1HNnYP83o16V1th8mhPvk
w1RKiKFY12lMui01658yeVAGr6y7CRVwDXcRal1mzkaWRMtLk/QAGsBTUZA6x4bx
5uDMCkpz5oW8N6hfmEDOYTXq38DsB9f2h4G5T4GLMCl3fHvo/VQ+0arUBNzM2zPd
fK/XNO8/J51ZyF6Fwdwk9gc=
-----END ENCRYPTED PRIVATE KEY-----
```

使用图片中的密码解密私钥得

```bash
openssl rsa -in encrypted_private_key.pem -out decrypted_private_key.pem
```

```
-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALbLJIWZOSeu2Re3
lLtjQJ3j01CnYvebhUzXexP5YpNeRpGqb0MM2TYAtlF4cDckaUUEjL7oy7pkp4/6
eT/BIpR72c50udejdxEc4yiq4/emIJHAYDKdkYq6VWM0DjiAxfqAdK33USAai8C3
QDcCgkufXxHg2V2mf6uSsV4FcOmhAgMBAAECgYEAkBAsWYq4C/l2qYWLF+CSdZ2v
1poFmsYcWcJeAxECSsj7byRXCg4fRrtq9WypbBwrRzTdxDxvDBj2IrgyRTfvCqZD
s48y3vvnyvVi/CezOuMZGSgOEuDobmquF/ldYxhx3WC/1Gz/5/KkOyhI9x8KCyQq
sUVlQXtse0gNYj0E6AECQQDxb4l+tnz4/kcK3s0dWu/FJAuJBdKSP321fusaVBUT
bGG1gbRPUTs7nh10XA7DHolcZuKI+ve4kqD56TDGfN1BAkEAwdIAY/eoAr7RcxFC
4btQndK3XhSrZUREAkrqRwf+ymudMOKagpy82wWT7wjHEZACFpxtDyWNUGdXMICO
YNgUYQJAN2cv9xrrXLwFE3KDQSw//05BM2VZp+PX9hE05CrNV1K0rVEhTl5GqGyl
N7F0VcQpI0Ic0/A7bmh/djnTzoiSwQJBAIHIiRJnh00vUTjn2g0lTLohmz+YP5yz
tYaDe5TMucP5g2x0kFndcmiGt6RcEFCmSX+yhySZVKL+T9fefXhDuIECQQDGcvmg
NphtxQC21Kp0H43gfgIsrmA53DCUgKT5yw0Kl325nv/ZQg7kX254+/7w4aPauSK4
8teA02fR+n2JOxKd
-----END PRIVATE KEY-----
```

然后用这个私钥解密上面的`acc_flag`

```bash
echo "tJkjkC9zdTfV/vjWjKBQERPvbJB+MTzNgv9Q7OsSeW9VO+cz9GM7gdfFu3+UwSfKp3OStBv6wESZitD8x9rR8Jx4LwKU+i1ysKUQWOvORYSSif1zt37ored1r1IALNX1jKEWRMZXTQU07kNULKk3Zve7Q8qTnbGviNqFjG3W4s0=" | base64 -d > encrypted_data.bin
openssl pkeyutl -decrypt -inkey decrypted_private_key.pem -in encrypted_data.bin
```

得到`flag{12grd058g95-4gi698-g5mjt1m299-tgrtjhn570te45hur0t-t9kftt97n0b8}`

