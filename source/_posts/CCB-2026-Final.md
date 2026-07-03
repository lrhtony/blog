---
title: 2026 长城杯 决赛 部分Writeup
comments: true
date: 2026-07-03 14:16:58
tags:
  - CTF
  - 逆向
categories:
  - 技术
---

没有 AI 参与，纯手打的一场比赛。拿了个二血，可惜忘记截图了。记录一下我做的部分。估计也是我的最后一次人工打 CTF 了，因此可能是最后一篇 Writeup。现在 CTF 变成 AI 大战，看看谁的提示词厉害谁的 token 多谁最能破限。

## Reverse

### UnityCore

il2cpp 游戏，先使用 Il2CppDumper 还原符号

![](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/2687d4b8fe319bc4f440516b3acede2e140b7f6ddb2bd820c596c2b9d6b73717.webp)

据说有人卡在这里，似乎是 Il2CppDumper 的配置项要修改，我可能以前用的时候修改过了？

IDA 打开二进制文件发现加壳了，也无法直接调试，DIE 查壳

![](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/1e53fd02f549e5121e4a5d94bc3afccac9ef8de8803d530c96eae8fb9e2fbb3a.webp)

没见过这种壳，就想着x64dbg脱

![image-20260703153139064](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/c3445006ba469a05b6a9ed6e7f01e5c72f24c56ec4cffcc00af84b4fe35eabc9.webp)

当然被检测。刚好 ScyllaHide 插件有针对这种壳的绕过，直接应用。

![image-20260703153526195](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/a3c04f7e6ca8ce5ea89a700610149457b386704c2aac810f8442a6c26c48d8fe.webp)

然后就能开着调试运行起来了。接着就运行过程中直接 dump

![image-20260703153737861](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/9004573d003e299aa8c4f387cfde80506d9342f95a32d2c10c109ef3e00c86a5.webp)

用 Il2CppDumper 恢复符号即可。在`xYz987$$check_input`可找到输入处理以及加密逻辑

![image-20260703154257225](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/86988484437caad8dfb96e2b5ab09f0bd46a5670e8a14cedda2f7b39d334cff2.webp)

点进 AES 加密函数可以看到 AES 密钥填充`0`到32位，还有 iv

![image-20260703155537477](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/f97367a069364c89ed17ecd712626159aefc6086cc32d1310bfdfe3fa39ade9e.webp)

因此考虑断点+动态调试获取以上所有内容

通过 IDA 的悬浮提示可知 AES 加密函数的 key 在 r8 寄存器，结合结构体信息，并在函数开头断点

![image-20260703161502654](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/398b1f82baf797367eb6254533d2f6085e3b7e3a5fd0e7be4cdbf5f38bff8aac.webp)

![image-20260703161506580](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/b8bc95dc4b916a82ef256d9b41efba2b48f9b2f8b9ca54b61c5bea85bd74816f.webp)

![image-20260703161536501](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/949d02d6c1ee3921a6eb2d6e29a87b1622c7236e5073bacf4fc22706ae9651dd.webp)

可以得到 key 是 `asdfg65432`，后面补`0`到 32 位

密文在反编译按<kbd>Tab</kbd> 定位到

![image-20260703163002680](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/0c0ac6e4c136f3e2594a6ed5d31f99011caea984fc1766dd18e28b55b85e648c.webp)

下断点 rdx 定位到密文

![image-20260703163236762](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/af3ec82a0e9fc67323968fbfa389bc650855880702658c8eaab714cf1af7b9d0.webp)

同样的，iv也用类似方法得到 `1234567890ABCDEF`

![image-20260703164239547](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/05ae2ad6d6e57f90dce1701a287539a9590922caecb816388b0c0a178362679b.webp)

最后直接解密就可以得到`flag{cc697aa6-42b6-4341-9bed-6b5cc5c603fd}`

![image-20260703164320750](https://img.0a0.moe/blog/2026/07/03/2026-%E9%95%BF%E5%9F%8E%E6%9D%AF-%E5%86%B3%E8%B5%9B-%E9%83%A8%E5%88%86writeup/308774bb194795a02e3f56dd430b19949af40c0b65c25a0db92f37599807cbd5.webp)

### notjavaweb

通过 Jadx 反编译，表面上是评分系统，实际上是通过接口编写 VM 和执行。接口在`com.example.moviereview.controller.UserController`，解释运行在`com.example.moviereview.analytics.AnalyticsReportGenerator`

用脚本提取一下抓包数据，虽然用了下本地 AI，发现写出来还是一坨，自己改了下

```python
import re
from typing import List, Union

def extract_data_from_lines(text: str) -> List[Union[int, str]]:
    """
    逐行扫描文本，从两种特定格式的JSON中提取数据：
    1. {"emojiAvatarId": N} -> 提取 N (int)
    2. {"movieId": N, "rating": N, "content": "data[...]" } -> 提取 "data[...]" (str)
    
    所有提取的数据将统一存储到一个列表中。
    
    Args:
        text: 包含待提取信息的多行字符串。
        
    Returns:
        一个包含所有提取到的值（int或str）的列表。
    """
    all_extracted_values: List[Union[int, str]] = []

    # 模式 1: 提取 Emoji ID (匹配整个结构，并捕获内部的数字)
    # \s* 允许ID前后有空格
    regex_emoji_id = r'\{"emojiAvatarId":\s*(\d+)\}'

    # 模式 2: 提取 Movie Content (更精确的捕获内容：匹配到 "content": "..." 结构)
    # 捕获组 (.*?) 捕获引号内的所有内容。
    regex_movie_data = r'\{"movieId":\s*\d+,\s*"rating":\s*\d+,\s*"content":\s*"([^"]*)"\s*\}'

    # 1. 将文本按行分割，并遍历每一行
    lines = text.splitlines()
    
    print(f"--- 开始扫描 {len(lines)} 行数据 ---")

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue # 跳过空行

        # 2. 尝试匹配 模式 1 (Emoji ID)
        emoji_matches = re.findall(regex_emoji_id, line)
        for match in emoji_matches:
            # 匹配结果是字符串，需要转换为整数
            try:
                id_value = int(match)
                all_extracted_values.append(id_value)
                print(f"[行 {i+1} - ID模式] 成功提取 ID: {id_value}")
            except ValueError:
                pass # 如果转换失败，则跳过

        # 3. 尝试匹配 模式 2 (Movie Data)
        movie_matches = re.findall(regex_movie_data, line)
        for match in movie_matches:
            # 捕获组的内容已经是字符串，直接添加
            content_value = match
            all_extracted_values.append(content_value[5:-1])
            all_extracted_values.append(content_value[5:-1])
            print(f"[行 {i+1} - Movie模式] 成功提取 Content: '{content_value}'")

    return all_extracted_values

# ===============================================
# 示例使用
# ===============================

multi_line_text = """
POST /api/register HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Content-Length: 54
Content-Type: application/json

{"username": "hacker_8733", "password": "password123"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":21,"username":"hacker_8733","emojiAvatarId":1}}
POST /api/login HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Content-Length: 54
Content-Type: application/json

{"username": "hacker_8733", "password": "password123"}
HTTP/1.1 200 
Set-Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D; Path=/; HttpOnly
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":21,"username":"hacker_8733","emojiAvatarId":1}}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 60
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[/payload.enc]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":357,"movieId":1,"userId":21,"rating":5,"content":"data[/payload.enc]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 10}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 17}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[0]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":358,"movieId":1,"userId":21,"rating":5,"content":"data[0]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 51
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[102]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":359,"movieId":1,"userId":21,"rating":5,"content":"data[102]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:39 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[2]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":360,"movieId":1,"userId":21,"rating":5,"content":"data[2]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[2]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":361,"movieId":1,"userId":21,"rating":5,"content":"data[2]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 23}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 50
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[58]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":362,"movieId":1,"userId":21,"rating":5,"content":"data[58]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 22}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[3]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":363,"movieId":1,"userId":21,"rating":5,"content":"data[3]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[2]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:40 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":364,"movieId":1,"userId":21,"rating":5,"content":"data[2]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 11}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 20}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 26}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[1]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":365,"movieId":1,"userId":21,"rating":5,"content":"data[1]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 13}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[2]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":366,"movieId":1,"userId":21,"rating":5,"content":"data[2]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 23}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[4]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":367,"movieId":1,"userId":21,"rating":5,"content":"data[4]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[3]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":368,"movieId":1,"userId":21,"rating":5,"content":"data[3]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[2]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":369,"movieId":1,"userId":21,"rating":5,"content":"data[2]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 25}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 12}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 26}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 50
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[55]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":370,"movieId":1,"userId":21,"rating":5,"content":"data[55]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 13}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 20}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:42 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 26}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 20}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[1]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":371,"movieId":1,"userId":21,"rating":5,"content":"data[1]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 24}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 20}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 49
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[7]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":372,"movieId":1,"userId":21,"rating":5,"content":"data[7]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 18}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 21}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 26}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 26}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 26}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 64
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[/tmp/payload_run]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":373,"movieId":1,"userId":21,"rating":5,"content":"data[/tmp/payload_run]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 15}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 73
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[chmod +x /tmp/payload_run]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:43 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":374,"movieId":1,"userId":21,"rating":5,"content":"data[chmod +x /tmp/payload_run]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 16}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:44 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/reviews/add HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 64
Content-Type: application/json

{"movieId": 1, "rating": 5, "content": "data[/tmp/payload_run]"}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:44 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":{"id":375,"movieId":1,"userId":21,"rating":5,"content":"data[/tmp/payload_run]"}}
POST /api/user/avatar HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 21
Content-Type: application/json

{"emojiAvatarId": 16}
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 10 Apr 2026 06:55:44 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{"code":0,"message":"success","data":null}
POST /api/logout HTTP/1.1
Host: 192.168.117.136:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, zstd
Accept: */*
Connection: keep-alive
Cookie: JSESSIONID=7AAB83912F3A4EF2BEFA0CB197B46F1D
Content-Length: 0

"""

# 执行函数
final_list = extract_data_from_lines(multi_line_text)

# 打印最终结果
print("\n" + "="*50)
print("🎉 所有数据提取完成。")
print("最终统一存储的列表 (List[Union[int, str]]):")
print(final_list)
print(len(final_list))
```

提取出这样的数据

```
"payload.enc", "payload.enc", 10, 17, "0", "0", 18, "102", "102", 18, "2", "2", 18, 25, "2", "2", 18, 25, 23, "58", "58", 18, 22, "3", "3", 18, 25, "2", "2", 18, 25, 11, 20, 26, "1", "1", 18, 25, 13, "2", "2", 18, 25, 23, "4", "4", 18, 25, "3", "3", 18, 25, "2", "2", 18, 25, 12, 26, "55", "55", 18, 13, 20, 26, 20, "1", "1", 18, 24, 20, "7", "7", 18, 21, 26, 26, 26, "payload_run", "payload_run", 15, "chmod +x /tmp/payload_run", "chmod +x /tmp/payload_run", 16, "/tmp/payload_run", "/tmp/payload_run", 16
```

然后在原先的 VM 解释器上改一改，使其能够跑起来，并输出怎么跑的

```
0 PUSH /payload.enc
1 ReadFile                                    栈顶 文件内容
2 Len STACK[0]                                栈顶 文件长度
3 PUSH 0                                      
4 To Int STACK[0]                             栈顶0
5 PUSH 102
6 To Int STACK[0]                             栈顶102
7 PUSH 2
8 To Int STACK[0]                             栈顶2
9 GET Stack idx:STACK[0]                      栈顶 stack[2] -> 文件长度
10 PUSH 2
11 To Int STACK[0]                            栈顶2
12 GET Stack idx:STACK[0]                    栈顶stack[2] -> 0
13 PLUS STACK[0] STACK[1]                     文件长度 - 0
14 PUSH 58
15 To Int STACK[0]                            栈顶58
16 JMPIF STACK[0] STACK[1]                    挑转到58，如果 文件长度-0=0
17 PUSH 3
18 To Int STACK[0]                            栈顶3
19 GET Stack idx:STACK[0]                     栈顶s tack[3] -> 文件内容
20 PUSH 2
21 To Int STACK[0]                            栈顶2
22 GET Stack idx:STACK[0]                     栈顶stack[2] -> 现在取的序号
23 GET STACK[1] INDEX[0]                      读出文件内容
24 Exchange STACK[0] STACK[1]                 交换文件内容以及读出的字节
25 POP STACK                                  pop掉文件内容
26 PUSH 1
27 To Int STACK[0]                            栈顶1
28 GET Stack idx:STACK[0]                     上面神秘的102
29 XOR STACK[0] STACK[1]                      异或读出的文件内容和102
30 PUSH 2
31 To Int STACK[0]                            栈顶2
32 GET Stack idx:STACK[0]                     文件idx
33 PLUS STACK[0] STACK[1]                     异或的 - idx

34 PUSH 4
35 To Int STACK[0]
36 GET Stack idx:STACK[0]                     文件内容
37 PUSH 3          
38 To Int STACK[0]
39 GET Stack idx:STACK[0]                     idx
40 PUSH 2
41 To Int STACK[0]
42 GET Stack idx:STACK[0]                     异或完减完idx的值
43 SET STACK[2] idx STACK[1] to STACK[0]      设置回去

44 POP STACK
45 PUSH 55
46 To Int STACK[0]
47 XOR STACK[0] STACK[1]                    上面的值异或55
48 Exchange STACK[0] STACK[1]               
49 POP STACK                                 取代102
50 Exchange STACK[0] STACK[1]
51 PUSH 1
52 To Int STACK[0]
53 ADD STACK[0] STACK[1]                    +1  文件的idx
54 Exchange STACK[0] STACK[1]
55 PUSH 7
56 To Int STACK[0]
57 JMP STACK[0]                               跳回到7
58 POP STACK
59 POP STACK
60 POP STACK
61 PUSH /tmp/payload_run
62 WRITE STACK[0] to STACK[1]
63 PUSH chmod +x /tmp/payload_run
64 EXECUTE STACK[0]
65 PUSH /tmp/payload_run
66 EXECUTE STACK[0]
```

然后人肉反编译，得到如下的逻辑

```python
import os

input_file = "payload.enc"
output_file = "decrypt"


with open(input_file, 'rb') as f:
    raw_data = f.read()

tmp = 102

encrypted_data = bytearray()
for index, b in enumerate(raw_data):
    transformed = b ^ tmp
    transformed = transformed - index
    transformed = transformed % 256
    encrypted_data.append(transformed)
    tmp = transformed ^ 55

with open(output_file, 'wb') as f:
    f.write(encrypted_data)
        
    print(f"加密完成！结果已保存至: {output_file}")
    print(f"处理了 {len(raw_data)} 字节。")
```

然后以为抓包后面的密文解密就是 flag，整了半天后发现不是，发现就是 jar 包里的 payload.enc

解密后发现是个 Rust 二进制程序，使用 IDA反编译后主要逻辑都在`payload::main()`函数里

程序读取了本地的 flag 后，使用魔改 AES 加密发送。比赛的时候就看出了 S 盒被魔改，还有列混合有点问题，怎么改脚本都没做出来。手撕完 VM 还要看这 Rust AES 魔改是真的难受。后面丢 AI，5 min不到就做出来了😭 。贴个最后的 AI 脚本。

```python
SBOX = [0xC5, 0xEA, 0xB8, 0x6C, 0x91, 0xA2, 0x11, 0x44, 0x05, 0xBA, 0x76, 0x99, 0x45, 0x53, 0xEF, 0x54, 0xA5, 0xF9, 0x90, 0x06, 0xF6, 0x28, 0xEB, 0x48, 0x85, 0x66, 0x64, 0x5C, 0x3A, 0x0E, 0xE7, 0x1B, 0xF5, 0x70, 0xDB, 0xA1, 0x6F, 0xE4, 0xCE, 0xCF, 0xB6, 0xE2, 0xD9, 0xA4, 0xD2, 0xB2, 0xE9, 0xC7, 0xE5, 0x9D, 0xFE, 0x2E, 0xFF, 0x84, 0x09, 0x50, 0xD0, 0x41, 0x20, 0x5F, 0xD4, 0x4D, 0xAA, 0x61, 0xDD, 0x15, 0x1F, 0x26, 0xCA, 0xFD, 0x1D, 0xBD, 0x7A, 0x57, 0xBF, 0x46, 0x40, 0xB3, 0x2A, 0x93, 0x96, 0x39, 0x56, 0xBE, 0xCB, 0x9C, 0x9F, 0xF1, 0x4E, 0x49, 0x7E, 0x8E, 0xD3, 0xB9, 0xC4, 0xFA, 0xD5, 0x67, 0x03, 0x1A, 0x58, 0x55, 0x30, 0x7F, 0x32, 0xC3, 0x8F, 0xDF, 0xA3, 0xD1, 0x0F, 0xDA, 0x4F, 0x88, 0x6D, 0xC1, 0x37, 0xD6, 0x62, 0x17, 0xA7, 0x19, 0x6B, 0x27, 0x98, 0xA9, 0x7D, 0x0C, 0x23, 0x82, 0xAD, 0x52, 0x42, 0x68, 0xDE, 0x1E, 0xA8, 0x3B, 0x33, 0x3D, 0x43, 0x9B, 0x13, 0x0B, 0xF0, 0xCC, 0x8C, 0x01, 0x12, 0x75, 0xEE, 0x47, 0x07, 0x8B, 0x14, 0x2B, 0xD8, 0xAE, 0x04, 0x87, 0x86, 0xDC, 0xBB, 0xE8, 0xE6, 0x3C, 0x78, 0x77, 0xC2, 0xE0, 0x69, 0x29, 0x02, 0xB1, 0x35, 0xB5, 0x00, 0x7C, 0x83, 0xC8, 0x18, 0x8A, 0x60, 0x36, 0x24, 0xC9, 0xFB, 0x38, 0xAF, 0x80, 0xB0, 0x31, 0xCD, 0x59, 0x94, 0xC6, 0x4C, 0xD7, 0xC0, 0x71, 0xE1, 0xED, 0x8D, 0x79, 0x3F, 0x4B, 0x72, 0x9E, 0x3E, 0x08, 0x2C, 0x9A, 0x0A, 0x63, 0x22, 0x5B, 0x1C, 0x5A, 0x25, 0xF8, 0x4A, 0xF7, 0xA0, 0xE3, 0x6A, 0x2F, 0x89, 0x74, 0x7B, 0x5E, 0x2D, 0x5D, 0xBC, 0x95, 0xA6, 0x0D, 0x16, 0xFC, 0xAC, 0x34, 0xF4, 0x51, 0xAB, 0x6E, 0x92, 0xEC, 0xB4, 0x97, 0x81, 0x65, 0xF3, 0xB7, 0x73, 0x10, 0x21, 0xF2]

def get_inverse_sbox(sbox):
    """
    通过给定的 S-Box 计算其逆 S-Box
    :param sbox: 包含 256 个元素的列表 (AES S-Box)
    :return: 逆 S-Box 列表
    """
    # 初始化一个长度为 256 的列表，初始值为 0
    inv_sbox = [0] * 256
    
    # 遍历原 S-Box
    # i 是输入 (index)，val 是输出 (value)
    # 原关系：sbox[i] = val
    # 逆关系：inv_sbox[val] = i
    for i in range(256):
        val = sbox[i]
        inv_sbox[val] = i
        
    return inv_sbox

# AES 逆 S-box
INV_SBOX = get_inverse_sbox(SBOX)


# RCON table from the binary at 0x6A70. The code indexes it as RCON[k >> 2].
CUSTOM_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

# Data from the binary
IV = bytes([0x8E, 0x1A, 0xF6, 0x55, 0x30, 0xC9, 0x74, 0xBB, 0x2D, 0x97, 0x4E, 0x11, 0x60, 0xDA, 0xA7, 0x3C])

KEY = bytes([0x4A, 0x7F, 0x2C, 0x91, 0xB3, 0x5E, 0xD8, 0x16, 0xFA, 0x43, 0x09, 0xCC, 0x7B, 0xE5, 0x28, 0x3D])

CIPHERTEXT_HEX = (
    "08a76a304f8a7d64baace233c30d8e78"
    "9e27ec1ae589e7b36252ea00ecf2a9c2"
    "74b18754f4758095956a08dc1c6793e0"
    "7cf91658ae232ac3935aa17c03294a62"
    "5c90ba2ef4b482ffb145388829ed5554"
)
CIPHERTEXT = bytes.fromhex(CIPHERTEXT_HEX)

def gmul(a, b):
    """Galois Field multiplication in GF(2^8)"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p

def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]

def inv_shift_rows(state):
    """Inverse of the binary's row-major ShiftRows table [0, 3, 1, 2]."""
    out = [0] * 16
    shifts = [0, 3, 1, 2]
    for row, shift in enumerate(shifts):
        base = row * 4
        for col in range(4):
            out[base + ((shift + col) & 3)] = state[base + col]
    return out

def mix_columns(state):
    """Standard AES MixColumns on the binary's row-major state."""
    out = list(state)
    for c in range(4):
        s0, s1, s2, s3 = state[c], state[4+c], state[8+c], state[12+c]
        out[c]      = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3
        out[4 + c]  = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3
        out[8 + c]  = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3)
        out[12 + c] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2)
    return out

def inv_mix_columns(state):
    """Standard AES InvMixColumns on the binary's row-major state."""
    out = list(state)
    for c in range(4):
        s0, s1, s2, s3 = state[c], state[4+c], state[8+c], state[12+c]
        out[c]      = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9)
        out[4 + c]  = gmul(s0, 9)  ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13)
        out[8 + c]  = gmul(s0, 13) ^ gmul(s1, 9)  ^ gmul(s2, 14) ^ gmul(s3, 11)
        out[12 + c] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9)  ^ gmul(s3, 14)
    return out

def key_expansion(key, nk=4, nr=10, rcon=CUSTOM_RCON):
    """AES-128-style key expansion with the binary's custom S-box."""
    total_words = 4 * (nr + 1)
    w = [0] * (total_words * 4)
    
    # Copy initial key
    for i in range(nk * 4):
        w[i] = key[i]
    
    for i in range(nk, total_words):
        # Get previous word
        temp = [w[4*(i-1)], w[4*(i-1)+1], w[4*(i-1)+2], w[4*(i-1)+3]]
        
        if i % nk == 0:
            # RotWord
            temp = [temp[1], temp[2], temp[3], temp[0]]
            # SubWord
            temp = [SBOX[b] for b in temp]
            # XOR with rcon
            temp[0] ^= rcon[i // nk]
        for j in range(4):
            w[4*i + j] = w[4*(i - nk) + j] ^ temp[j]
    
    # Return as list of round keys (each 16 bytes)
    round_keys = []
    for r in range(nr + 1):
        rk = w[r*16 : r*16 + 16]
        round_keys.append(rk)
    
    return round_keys

def add_round_key(state, round_key):
    out = list(state)
    for col in range(4):
        for row in range(4):
            out[4 * row + col] ^= round_key[4 * col + row]
    return out

def block_to_state(block):
    """The Rust code transposes each block before AES rounds."""
    state = [0] * 16
    for col in range(4):
        for row in range(4):
            state[4 * row + col] = block[4 * col + row]
    return state

def state_to_block(state):
    block = [0] * 16
    for col in range(4):
        for row in range(4):
            block[4 * col + row] = state[4 * row + col]
    return bytes(block)

def aes_decrypt_block(ciphertext, round_keys, nr=10):
    """Decrypt a single 16-byte block"""
    state = block_to_state(ciphertext)
    
    # Initial AddRoundKey with last round key
    state = add_round_key(state, round_keys[nr])
    
    # Rounds nr-1 down to 1
    for r in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
    
    # Last round (no InvMixColumns)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    
    return state_to_block(state)

def cbc_decrypt(ciphertext, key, iv, rcon=CUSTOM_RCON):
    """Decrypt the binary's AES-like CBC mode."""
    round_keys = key_expansion(key, rcon=rcon)
    
    plaintext = bytearray()
    prev_block = iv
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = aes_decrypt_block(block, round_keys)
        # XOR with previous ciphertext block (or IV for first block)
        pt_block = bytes(d ^ p for d, p in zip(decrypted, prev_block))
        plaintext.extend(pt_block)
        prev_block = block
    
    return bytes(plaintext)


decrypted = cbc_decrypt(CIPHERTEXT, KEY, IV, rcon=CUSTOM_RCON)
pad = decrypted[-1]
if 0 < pad <= 16 and decrypted.endswith(bytes([pad]) * pad):
    decrypted = decrypted[:-pad]
print(decrypted)
# flag{F1n@1ly_Y0u_G0t_Th1s_f1ag_and_f1nd_7h3_TRUTH_D0_Y0u_L1k3_1t?}
```

## 结语

就这样吧，反正人肯定会比不过 AI 的了（
