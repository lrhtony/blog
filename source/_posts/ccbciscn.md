---
title: 第十八届全国大学生信息安全竞赛（创新实践能力赛）（CISCN）暨第二届“长城杯”铁人三项赛（防护赛）部分Writeup
comments: true
date: 2024-12-17 21:47:44
tags:
  - CTF
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzf6pcjdha2fxvb2krlvxwlhgk2e
---

Misc好玩嘿嘿，逆向真不熟（

## 逆向工程

### ezCsky

使用Cutter查看汇编，可以得到

![img](https://img.0a0.moe/od/01tklsjzhlyfi7qmgbsjclwoeq3xxzy7hx)

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

![img](https://img.0a0.moe/od/01tklsjzc2yvctwnglgfdkiw6tnvmgoet2)

### rand0m

### cython

两道cpython再研究一下

## 威胁检测与网络流量分析

### zeroshell_1

排查http流量，发现

![img](https://img.0a0.moe/od/01tklsjze4ixxvwgf4ybhj7dwearjsn53h)

对Referer解base64得flag{6C2E38DA-D8E4-8D84-4A4F-E2ABD07A1F3A}

### zeroshell_2

对虚拟机磁盘文件使用FTK Imager进行提取，打开flag文件即可得

### zeroshell_3

对.nginx可疑隐藏文件分析，发现

![img](https://img.0a0.moe/od/01tklsjzef7fe27o4lp5gkidxdrtq52ugb)

提交ip

### zeroshell_4

即上面的.nginx

### zeroshell_5

![img](https://img.0a0.moe/od/01tklsjzfzytuge6cq5rb3ajfzzwde63yu)

在刚刚ip下面可发现字符串，查找引用即可确定为密钥

### zeroshell_6

使用vscode对/var/register/system文件夹下搜索恶意文件名，找到

![img](https://img.0a0.moe/od/01tklsjzdbfxr3tn33mfgzse6uufoowqbd)

即/var/register/system/startup/scripts/nat/File

### WinFT_1

使用CurrPorts发现外联

![img](https://img.0a0.moe/od/01tklsjzbmibsuqs6nwzdiclrdkpumujm4)

看不到域名，查找hosts文件

![img](https://img.0a0.moe/od/01tklsjzcmtomvrvxr25e3ynjtv5f2r4bt)

miscsecure.com:192.168.116.130:443

### WinFT_2

计算机管理计划任务里面发现flag

![img](https://img.0a0.moe/od/01tklsjzaumjmo7ipq5fhllrjf7d5cm3j7)

![img](https://img.0a0.moe/od/01tklsjzc6jspu2knp5ze3gfqxs2v3xoif)

### sc05_1

综合firewall几个表，在tcp-export中发现最早外联时间为 2024/11/09 16:22:42 

![img](https://img.0a0.moe/od/01tklsjzc2k5xpwilbsvejiy6i5lwgaxsf)

### Kiwi

对Kiwi进行逆向

![img](https://img.0a0.moe/od/01tklsjzgttjb4otgnzjb37rvs7n5n7ku3)

可以发现前面通过lsadump获取密钥，然后通过sub_140082974对数据加密，最后通过sub_140082774发送http://421aa90e079fa326b6494f812ad13e79.com/upload

加密部分为换表base64+随机数

![img](https://img.0a0.moe/od/01tklsjzh2oy7va7luuvbjl3qetfl5ssjt)

![img](https://img.0a0.moe/od/01tklsjza7rpyucionhzglielrxehyxagr)

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

![img](https://img.0a0.moe/od/01tklsjzbmfelzt6chgbclwslgavkrdbta)

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

![dump1](https://img.0a0.moe/od/01tklsjzczn72boi5nzzdjxteeqwbpl5gj)

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
openssl rsautl -decrypt -inkey decrypted_private_key.pem -in encrypted_data.bin -out decrypted_data.txt
```

得到`flag{12grd058g95-4gi698-g5mjt1m299-tgrtjhn570te45hur0t-t9kftt97n0b8}`

