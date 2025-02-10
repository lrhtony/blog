---
title: CTF逆向常见加密编码算法收集
comments: true
date: 2025-02-09 01:19:03
tags:
  - CTF
categories:
  - 技术
---
以便查找常量、查找算法魔改、线下比赛用

AI生成的，不保证正确


## 加密/编码算法

### RC4

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// RC4 加密/解密函数，in 与 out 可相同实现原地加解密
void rc4(const unsigned char *in, unsigned char *out, int length, const unsigned char *key, int key_length) {
    unsigned char S[256];
    int i, j = 0, k, t;

    // KSA: 初始化 S 数组并打乱顺序
    for (i = 0; i < 256; i++) {
        S[i] = (unsigned char)i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_length]) % 256;
        t = S[i];
        S[i] = S[j];
        S[j] = t;
    }

    // PRGA: 生成密钥流，并与输入数据异或
    i = 0;
    j = 0;
    for (k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        t = S[i];
        S[i] = S[j];
        S[j] = t;
        out[k] = in[k] ^ S[(S[i] + S[j]) % 256];
    }
}

int main() {
    // 示例明文和密钥
    const char *plaintext = "Hello, RC4!";
    const char *key = "SecretKey";
    int text_len = strlen(plaintext);
    int key_len = strlen(key);

    // 分配加解密数据缓冲区
    unsigned char *cipher = (unsigned char *)malloc(text_len);
    unsigned char *decrypted = (unsigned char *)malloc(text_len);

    // RC4 加密
    rc4((const unsigned char *)plaintext, cipher, text_len, (const unsigned char *)key, key_len);
    printf("明文: %s\n", plaintext);
    printf("加密后 (16进制): ");
    for (int i = 0; i < text_len; i++) {
        printf("%02X ", cipher[i]);
    }
    printf("\n");

    // RC4 解密（加密与解密操作相同）
    rc4(cipher, decrypted, text_len, (const unsigned char *)key, key_len);
    printf("解密后: %s\n", decrypted);

    free(cipher);
    free(decrypted);
    return 0;
}
```

```python
#!/usr/bin/env python3

# RC4 加密/解密函数，输入 data 和 key 均为 bytes 类型
def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    # KSA: 初始化并打乱 S 数组
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    result = bytearray()
    # PRGA: 生成密钥流，并与数据异或
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)

def main():
    plaintext = "Hello, RC4!"
    key = "SecretKey"
    print("明文:", plaintext)
    
    # 将字符串转换为 bytes
    data = plaintext.encode('utf-8')
    key_bytes = key.encode('utf-8')
    
    # RC4 加密
    cipher = rc4(data, key_bytes)
    print("加密后 (16进制):", cipher.hex().upper())
    
    # RC4 解密
    decrypted = rc4(cipher, key_bytes)
    print("解密后:", decrypted.decode('utf-8'))

if __name__ == "__main__":
    main()
```

### TEA

```c
#include <stdio.h>
#include <stdint.h>

// TEA 加密：对 64 位数据（v[0]和 v[1]）使用 128 位密钥 k[0..3] 加密
void tea_encrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = 0;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0;
    v[1] = v1;
}

// TEA 解密：对 64 位数据（v[0]和 v[1]）使用 128 位密钥 k[0..3] 解密
void tea_decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = delta * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}

int main() {
    // 示例 64 位数据块和 128 位密钥
    uint32_t v[2] = {0x12345678, 0x9ABCDEF0};
    uint32_t k[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};

    printf("明文    : %08X %08X\n", v[0], v[1]);
    
    tea_encrypt(v, k);
    printf("加密后  : %08X %08X\n", v[0], v[1]);
    
    tea_decrypt(v, k);
    printf("解密后  : %08X %08X\n", v[0], v[1]);
    
    return 0;
}
```

```python
#!/usr/bin/env python3

# TEA 加密：输入 v 为 (v0, v1)，k 为 (k0, k1, k2, k3)，返回加密后的 (v0, v1)
def tea_encrypt(v, k):
    v0, v1 = v
    delta = 0x9e3779b9
    s = 0
    for _ in range(32):
        s = (s + delta) & 0xffffffff
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
    return (v0, v1)

# TEA 解密：输入 v 为 (v0, v1)，k 为 (k0, k1, k2, k3)，返回解密后的 (v0, v1)
def tea_decrypt(v, k):
    v0, v1 = v
    delta = 0x9e3779b9
    s = (delta * 32) & 0xffffffff
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        s = (s - delta) & 0xffffffff
    return (v0, v1)

def main():
    # 示例 64 位数据块和 128 位密钥
    v = (0x12345678, 0x9ABCDEF0)
    k = (0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210)
    print("明文    : %08X %08X" % v)
    encrypted = tea_encrypt(v, k)
    print("加密后  : %08X %08X" % encrypted)
    decrypted = tea_decrypt(encrypted, k)
    print("解密后  : %08X %08X" % decrypted)

if __name__ == "__main__":
    main()
```

### XTEA

```c
#include <stdio.h>
#include <stdint.h>

// XTEA 加密函数：对 64 位数据 v[0] 和 v[1] 使用 128 位密钥 k[0..3] 进行加密
void xtea_encrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0, delta = 0x9E3779B9;
    for (int i = 0; i < 32; i++) {
        v0 += ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]));
        sum += delta;
        v1 += ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]));
    }
    v[0] = v0;
    v[1] = v1;
}

// XTEA 解密函数：对 64 位数据 v[0] 和 v[1] 使用 128 位密钥 k[0..3] 进行解密
void xtea_decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]));
        sum -= delta;
        v0 -= ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]));
    }
    v[0] = v0;
    v[1] = v1;
}

int main() {
    // 示例 64 位数据块和 128 位密钥
    uint32_t v[2] = {0x12345678, 0x9ABCDEF0};
    uint32_t k[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
    
    printf("明文      : %08X %08X\n", v[0], v[1]);
    xtea_encrypt(v, k);
    printf("加密后    : %08X %08X\n", v[0], v[1]);
    xtea_decrypt(v, k);
    printf("解密后    : %08X %08X\n", v[0], v[1]);
    
    return 0;
}
```

```python
#!/usr/bin/env python3

# XTEA 加密函数，输入 v 为 (v0, v1)，k 为 (k0, k1, k2, k3)，返回加密后的 (v0, v1)
def xtea_encrypt(v, k):
    v0, v1 = v
    delta = 0x9e3779b9
    s = 0
    for i in range(32):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xffffffff
        s = (s + delta) & 0xffffffff
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xffffffff
    return (v0, v1)

# XTEA 解密函数，输入 v 为 (v0, v1)，k 为 (k0, k1, k2, k3)，返回解密后的 (v0, v1)
def xtea_decrypt(v, k):
    v0, v1 = v
    delta = 0x9e3779b9
    s = (delta * 32) & 0xffffffff
    for i in range(32):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xffffffff
        s = (s - delta) & 0xffffffff
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xffffffff
    return (v0, v1)

def main():
    # 示例 64 位数据块和 128 位密钥
    v = (0x12345678, 0x9ABCDEF0)
    k = (0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210)
    print("明文      : %08X %08X" % v)
    encrypted = xtea_encrypt(v, k)
    print("加密后    : %08X %08X" % encrypted)
    decrypted = xtea_decrypt(encrypted, k)
    print("解密后    : %08X %08X" % decrypted)

if __name__ == '__main__':
    main()
```

### XXTEA

```c
#include <stdio.h>
#include <stdint.h>

// XXTEA 加密：对 n 个 32 位整数的数据块 v 使用 128 位密钥 key 加密
void xxtea_encrypt(uint32_t *v, int n, const uint32_t key[4]) {
    if(n < 2) return;
    uint32_t delta = 0x9E3779B9;
    uint32_t rounds = 6 + 52 / n;
    uint32_t sum = 0;
    uint32_t e, y, z = v[n - 1];
    int p;
    while(rounds-- > 0) {
        sum += delta;
        e = (sum >> 2) & 3;
        for(p = 0; p < n - 1; p++) {
            y = v[p + 1];
            v[p] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) 
                    ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
            z = v[p];
        }
        y = v[0];
        v[n - 1] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) 
                     ^ ((sum ^ y) + (key[((n - 1) & 3) ^ e] ^ z));
        z = v[n - 1];
    }
}

// XXTEA 解密：对 n 个 32 位整数的数据块 v 使用 128 位密钥 key 解密
void xxtea_decrypt(uint32_t *v, int n, const uint32_t key[4]) {
    if(n < 2) return;
    uint32_t delta = 0x9E3779B9;
    uint32_t rounds = 6 + 52 / n;
    uint32_t sum = rounds * delta;
    uint32_t e, y = v[0], z;
    int p;
    while(sum != 0) {
        e = (sum >> 2) & 3;
        for(p = n - 1; p > 0; p--) {
            z = v[p - 1];
            v[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) 
                     ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
            y = v[p];
        }
        z = v[n - 1];
        v[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) 
                 ^ ((sum ^ y) + (key[(0 & 3) ^ e] ^ z));
        y = v[0];
        sum -= delta;
    }
}

int main() {
    // 示例明文（32 位整数数组）和 128 位密钥
    uint32_t data[] = {0x12345678, 0x9ABCDEF0, 0xCAFEBABE, 0x0BADF00D};
    int n = sizeof(data) / sizeof(data[0]);
    uint32_t key[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};

    printf("明文:\n");
    for (int i = 0; i < n; i++) {
        printf("%08X ", data[i]);
    }
    printf("\n");

    xxtea_encrypt(data, n, key);
    printf("加密后:\n");
    for (int i = 0; i < n; i++) {
        printf("%08X ", data[i]);
    }
    printf("\n");

    xxtea_decrypt(data, n, key);
    printf("解密后:\n");
    for (int i = 0; i < n; i++) {
        printf("%08X ", data[i]);
    }
    printf("\n");

    return 0;
}
```

```python
#!/usr/bin/env python3

# XXTEA 加密函数：对列表 v（32 位整数）使用 128 位密钥 key 加密
def xxtea_encrypt(v, key):
    n = len(v)
    if n < 2:
        return v
    delta = 0x9e3779b9
    rounds = 6 + 52 // n
    s = 0
    z = v[-1]
    for _ in range(rounds):
        s = (s + delta) & 0xffffffff
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (key[(p & 3) ^ e] ^ z))
            v[p] = (v[p] + mx) & 0xffffffff
            z = v[p]
        y = v[0]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (key[((n - 1) & 3) ^ e] ^ z))
        v[-1] = (v[-1] + mx) & 0xffffffff
        z = v[-1]
    return v

# XXTEA 解密函数：对列表 v（32 位整数）使用 128 位密钥 key 解密
def xxtea_decrypt(v, key):
    n = len(v)
    if n < 2:
        return v
    delta = 0x9e3779b9
    rounds = 6 + 52 // n
    s = (rounds * delta) & 0xffffffff
    y = v[0]
    while s:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (key[(p & 3) ^ e] ^ z))
            v[p] = (v[p] - mx) & 0xffffffff
            y = v[p]
        z = v[-1]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (key[(0 & 3) ^ e] ^ z))
        v[0] = (v[0] - mx) & 0xffffffff
        y = v[0]
        s = (s - delta) & 0xffffffff
    return v

def main():
    # 示例明文（32 位整数列表）和 128 位密钥
    data = [0x12345678, 0x9ABCDEF0, 0xCAFEBABE, 0x0BADF00D]
    key = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]

    print("明文:")
    print(" ".join(f"{x:08X}" for x in data))

    enc_data = data.copy()
    xxtea_encrypt(enc_data, key)
    print("加密后:")
    print(" ".join(f"{x:08X}" for x in enc_data))

    dec_data = enc_data.copy()
    xxtea_decrypt(dec_data, key)
    print("解密后:")
    print(" ".join(f"{x:08X}" for x in dec_data))

if __name__ == "__main__":
    main()
```

### AES

还有+iv、CBC等这里没有

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// AES S-box
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// AES 逆 S-box
static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

// Rcon 数组
static const uint8_t Rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

// 将 16 字节密钥扩展为 176 字节轮密钥
void KeyExpansion(const uint8_t key[16], uint8_t roundKeys[176]) {
    memcpy(roundKeys, key, 16);
    int bytesGenerated = 16;
    int rconIteration = 1;
    uint8_t temp[4];
    while (bytesGenerated < 176) {
        memcpy(temp, roundKeys + bytesGenerated - 4, 4);
        if (bytesGenerated % 16 == 0) {
            // 循环移位
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // S-box 替换
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            temp[0] ^= Rcon[rconIteration++];
        }
        for (int i = 0; i < 4; i++) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}

// 将状态与轮密钥相加
void AddRoundKey(uint8_t state[16], const uint8_t roundKey[16]) {
    for (int i = 0; i < 16; i++)
        state[i] ^= roundKey[i];
}

// 字节替换（SubBytes）
void SubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

// 逆字节替换（InvSubBytes）
void InvSubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = inv_sbox[state[i]];
}

// 行移位（ShiftRows）
void ShiftRows(uint8_t state[16]) {
    uint8_t temp[16];
    memcpy(temp, state, 16);
    // Row0
    state[0]  = temp[0];  state[4]  = temp[4];  state[8]  = temp[8];  state[12] = temp[12];
    // Row1
    state[1]  = temp[5];  state[5]  = temp[9];  state[9]  = temp[13]; state[13] = temp[1];
    // Row2
    state[2]  = temp[10]; state[6]  = temp[14]; state[10] = temp[2];  state[14] = temp[6];
    // Row3
    state[3]  = temp[15]; state[7]  = temp[3];  state[11] = temp[7];  state[15] = temp[11];
}

// 逆行移位（InvShiftRows）
void InvShiftRows(uint8_t state[16]) {
    uint8_t temp[16];
    memcpy(temp, state, 16);
    // Row0
    state[0]  = temp[0];  state[4]  = temp[4];  state[8]  = temp[8];  state[12] = temp[12];
    // Row1
    state[1]  = temp[13]; state[5]  = temp[1];  state[9]  = temp[5];  state[13] = temp[9];
    // Row2
    state[2]  = temp[10]; state[6]  = temp[14]; state[10] = temp[2];  state[14] = temp[6];
    // Row3
    state[3]  = temp[7];  state[7]  = temp[11]; state[11] = temp[15]; state[15] = temp[3];
}

// 返回 x 乘以 2 在 GF(2^8) 中的结果
uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

// 字节乘法
uint8_t multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1)
            result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

// 列混合（MixColumns）
void MixColumns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        int col = c * 4;
        uint8_t s0 = state[col+0], s1 = state[col+1], s2 = state[col+2], s3 = state[col+3];
        state[col+0] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
        state[col+1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
        state[col+2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
        state[col+3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
    }
}

// 逆列混合（InvMixColumns）
void InvMixColumns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        int col = c * 4;
        uint8_t s0 = state[col+0], s1 = state[col+1], s2 = state[col+2], s3 = state[col+3];
        state[col+0] = multiply(s0,0x0e) ^ multiply(s1,0x0b) ^ multiply(s2,0x0d) ^ multiply(s3,0x09);
        state[col+1] = multiply(s0,0x09) ^ multiply(s1,0x0e) ^ multiply(s2,0x0b) ^ multiply(s3,0x0d);
        state[col+2] = multiply(s0,0x0d) ^ multiply(s1,0x09) ^ multiply(s2,0x0e) ^ multiply(s3,0x0b);
        state[col+3] = multiply(s0,0x0b) ^ multiply(s1,0x0d) ^ multiply(s2,0x09) ^ multiply(s3,0x0e);
    }
}

// 对 16 字节数据块进行 AES 加密
void AES_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t roundKeys[176]) {
    uint8_t state[16];
    memcpy(state, in, 16);
    AddRoundKey(state, roundKeys);  // 初始轮密钥加
    for (int round = 1; round < 10; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 160);
    memcpy(out, state, 16);
}

// 对 16 字节数据块进行 AES 解密
void AES_decrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t roundKeys[176]) {
    uint8_t state[16];
    memcpy(state, in, 16);
    AddRoundKey(state, roundKeys + 160);
    for (int round = 9; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);
    memcpy(out, state, 16);
}

int main() {
    // 示例 16 字节明文与 16 字节密钥
    uint8_t plaintext[16] = {
        0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34
    };
    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };
    uint8_t roundKeys[176];
    uint8_t ciphertext[16], decrypted[16];

    KeyExpansion(key, roundKeys);
    AES_encrypt_block(plaintext, ciphertext, roundKeys);
    AES_decrypt_block(ciphertext, decrypted, roundKeys);

    printf("明文:      ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", plaintext[i]);
    }
    printf("\n加密后:    ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n解密后:    ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", decrypted[i]);
    }
    printf("\n");
    return 0;
}
```

```python
#!/usr/bin/env python3

# AES S-box
sbox = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# AES 逆 S-box
inv_sbox = [
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
]

# Rcon 数组
Rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

# 将 16 字节密钥扩展为 176 字节轮密钥
def KeyExpansion(key):
    roundKeys = list(key)
    bytesGenerated = 16
    rconIteration = 1
    temp = [0] * 4
    while bytesGenerated < 176:
        temp = roundKeys[bytesGenerated-4:bytesGenerated]
        if bytesGenerated % 16 == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[b] for b in temp]
            temp[0] ^= Rcon[rconIteration]
            rconIteration += 1
        for i in range(4):
            roundKeys.append(roundKeys[bytesGenerated - 16] ^ temp[i])
            bytesGenerated += 1
    return roundKeys

# 将状态与轮密钥相加
def AddRoundKey(state, roundKey):
    return [state[i] ^ roundKey[i] for i in range(16)]

# 字节替换（SubBytes）
def SubBytes(state):
    return [sbox[b] for b in state]

# 逆字节替换（InvSubBytes）
def InvSubBytes(state):
    return [inv_sbox[b] for b in state]

# 行移位（ShiftRows）
def ShiftRows(state):
    return [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]

# 逆行移位（InvShiftRows）
def InvShiftRows(state):
    return [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3]
    ]

# 返回 x 乘以 2 在 GF(2^8) 中的结果
def xtime(x):
    return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1

# 字节乘法
def multiply(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result

# 列混合（MixColumns）
def MixColumns(state):
    for c in range(4):
        col = c * 4
        s0, s1, s2, s3 = state[col:col+4]
        state[col+0] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
        state[col+1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
        state[col+2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
        state[col+3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)
    return state

# 逆列混合（InvMixColumns）
def InvMixColumns(state):
    for c in range(4):
        col = c * 4
        s0, s1, s2, s3 = state[col:col+4]
        state[col+0] = multiply(s0,0x0e) ^ multiply(s1,0x0b) ^ multiply(s2,0x0d) ^ multiply(s3,0x09)
        state[col+1] = multiply(s0,0x09) ^ multiply(s1,0x0e) ^ multiply(s2,0x0b) ^ multiply(s3,0x0d)
        state[col+2] = multiply(s0,0x0d) ^ multiply(s1,0x09) ^ multiply(s2,0x0e) ^ multiply(s3,0x0b)
        state[col+3] = multiply(s0,0x0b) ^ multiply(s1,0x0d) ^ multiply(s2,0x09) ^ multiply(s3,0x0e)
    return state

# 对 16 字节数据块进行 AES 加密
def AES_encrypt_block(plaintext, roundKeys):
    state = list(plaintext)
    state = AddRoundKey(state, roundKeys[:16])
    for round in range(1, 10):
        state = SubBytes(state)
        state = ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, roundKeys[round*16:(round+1)*16])
    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, roundKeys[160:])
    return state

# 对 16 字节数据块进行 AES 解密
def AES_decrypt_block(ciphertext, roundKeys):
    state = list(ciphertext)
    state = AddRoundKey(state, roundKeys[160:])
    for round in range(9, 0, -1):
        state = InvShiftRows(state)
        state = InvSubBytes(state)
        state = AddRoundKey(state, roundKeys[round*16:(round+1)*16])
        state = InvMixColumns(state)
    state = InvShiftRows(state)
    state = InvSubBytes(state)
    state = AddRoundKey(state, roundKeys[:16])
    return state

def main():
    # 示例 16 字节明文与 16 字节密钥
    plaintext = [
        0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34
    ]
    key = [
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    ]
    roundKeys = KeyExpansion(key)
    ciphertext = AES_encrypt_block(plaintext, roundKeys)
    decrypted = AES_decrypt_block(ciphertext, roundKeys)

    print("明文:      ", ' '.join(f'{x:02X}' for x in plaintext))
    print("加密后:    ", ' '.join(f'{x:02X}' for x in ciphertext))
    print("解密后:    ", ' '.join(f'{x:02X}' for x in decrypted))

if __name__ == "__main__":
    main()
```

### DES

```c
#include <stdio.h>
#include <stdint.h>

// IP（初始置换）表（1~64，下标值均按 1 开始）
static const int IP[64] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};

// FP（逆初始置换）表
static const int FP[64] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
};

// 扩展置换（将 32 位扩展为 48 位）
static const int E[48] = {
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
};

// P 置换（32 位）
static const int P[32] = {
    16,7,20,21,
    29,12,28,17,
    1,15,23,26,
    5,18,31,10,
    2,8,24,14,
    32,27,3,9,
    19,13,30,6,
    22,11,4,25
};

// DES 8 个 S-盒，每个盒 4 行16 列，共 64 个数
static const int S[8][64] = {
    { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
      0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
      4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
      15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 },
    { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
      3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
      0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
      13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 },
    { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
      13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
      13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
      1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 },
    { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
      13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
      10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
      3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 },
    { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
      14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
      4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
      11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 },
    { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
      10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
      9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
      4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 },
    { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
      13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
      1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
      6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 },
    { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
      1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
      7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
      2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
};

// PC-1 表（将 64 位密钥变为 56 位）
static const int PC1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

// PC-2 表（将 56 位变为 48 位轮密钥）
static const int PC2[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

// 每轮左移位数
static const int SHIFTS[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

// --- 辅助函数 ---
// 取 input 中从左数（MSB 为第 1 位）第 pos 位（1-indexed），输入总位数为 in_bits
int get_bit(uint64_t input, int pos, int in_bits) {
    return (input >> (in_bits - pos)) & 1;
}

// 根据置换表 table_len 个元素对 input 进行置换，input 有 in_bits 位
uint64_t permute(uint64_t input, const int *table, int table_len, int in_bits) {
    uint64_t output = 0;
    for (int i = 0; i < table_len; i++) {
        output = (output << 1) | get_bit(input, table[i], in_bits);
    }
    return output;
}

// 对 value（bits 位宽）作循环左移 shift 位
uint32_t left_rotate(uint32_t value, int shift, int bits) {
    return ((value << shift) | (value >> (bits - shift))) & ((1U << bits) - 1);
}

// --- 生成 16 个 48 位轮密钥 ---
void generate_round_keys(uint64_t key, uint64_t round_keys[16]) {
    // 先用 PC1 将 64 位密钥置换为 56 位
    uint64_t permuted_key = permute(key, PC1, 56, 64);
    // 分为左右各 28 位
    uint32_t C = (uint32_t)(permuted_key >> 28) & 0x0FFFFFFF;
    uint32_t D = (uint32_t)(permuted_key & 0x0FFFFFFF);
    for (int i = 0; i < 16; i++) {
        C = left_rotate(C, SHIFTS[i], 28);
        D = left_rotate(D, SHIFTS[i], 28);
        uint64_t combined = (((uint64_t)C) << 28) | D;  // 56 位
        round_keys[i] = permute(combined, PC2, 48, 56);
    }
}

// --- DES f 函数 ---
uint32_t des_f(uint32_t R, uint64_t round_key) {
    // 扩展 R 为 48 位
    uint64_t expanded_R = permute((uint64_t)R, E, 48, 32);
    // 异或轮密钥
    uint64_t x = expanded_R ^ round_key;
    uint32_t output = 0;
    // 8 个 S-盒替换，每次取 6 位
    for (int i = 0; i < 8; i++) {
        int shift = 42 - 6 * i; // 每个块 6 位，共 48 位
        uint8_t six_bits = (x >> shift) & 0x3F;
        int row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
        int col = (six_bits >> 1) & 0x0F;
        int s_val = S[i][row * 16 + col];
        output = (output << 4) | (s_val & 0x0F);
    }
    // P 置换
    uint32_t f_result = (uint32_t)permute((uint64_t)output, P, 32, 32);
    return f_result;
}

// --- DES 加密：对 64 位数据块 block 用 key 加密 ---
uint64_t des_encrypt(uint64_t block, uint64_t key) {
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);
    // 初始置换
    uint64_t permuted_block = permute(block, IP, 64, 64);
    uint32_t L = (uint32_t)(permuted_block >> 32);
    uint32_t R = (uint32_t)(permuted_block & 0xFFFFFFFF);
    // 16 轮 Feistel 结构
    for (int i = 0; i < 16; i++) {
        uint32_t temp = R;
        R = L ^ des_f(R, round_keys[i]);
        L = temp;
    }
    // 合并时交换左右
    uint64_t preoutput = (((uint64_t)R) << 32) | L;
    // 逆初始置换
    uint64_t cipher = permute(preoutput, FP, 64, 64);
    return cipher;
}

// --- DES 解密：与加密过程相同，只是轮密钥顺序相反 ---
uint64_t des_decrypt(uint64_t block, uint64_t key) {
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);
    uint64_t permuted_block = permute(block, IP, 64, 64);
    uint32_t L = (uint32_t)(permuted_block >> 32);
    uint32_t R = (uint32_t)(permuted_block & 0xFFFFFFFF);
    for (int i = 15; i >= 0; i--) {
        uint32_t temp = L;
        L = R ^ des_f(L, round_keys[i]);
        R = temp;
    }
    uint64_t preoutput = (((uint64_t)L) << 32) | R;
    uint64_t plain = permute(preoutput, FP, 64, 64);
    return plain;
}

// --- 示例：主函数 ---
int main() {
    // 示例明文与密钥（8 字节，以 16 进制表示）
    uint64_t plaintext = 0x0123456789ABCDEFULL;
    uint64_t key = 0x133457799BBCDFF1ULL;  // 示例密钥
    uint64_t cipher = des_encrypt(plaintext, key);
    uint64_t decrypted = des_decrypt(cipher, key);
    printf("明文:      %016llX\n", plaintext);
    printf("加密后:    %016llX\n", cipher);
    printf("解密后:    %016llX\n", decrypted);
    return 0;
}
```

```python
#!/usr/bin/env python3

# DES 置换表、S-盒及密钥调度表

IP = [
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
]

FP = [
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
]

E = [
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
]

P = [
    16,7,20,21,
    29,12,28,17,
    1,15,23,26,
    5,18,31,10,
    2,8,24,14,
    32,27,3,9,
    19,13,30,6,
    22,11,4,25
]

S = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
     0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
     15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
     3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
     13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
     13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
     1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
     13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
     3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
     14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
     11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
     10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
     4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
     13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
     6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
     1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
     2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
]

PC1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# --- 辅助函数 ---
# 取 input 中从左数第 pos 位（1-indexed），input 有 in_bits 位
def get_bit(input, pos, in_bits):
    return (input >> (in_bits - pos)) & 1

# 置换函数：根据 table 对 input 置换，table_len 为置换表长度，input 有 in_bits 位
def permute(input, table, table_len, in_bits):
    output = 0
    for pos in table:
        output = (output << 1) | get_bit(input, pos, in_bits)
    return output

# 对 value（bits 位宽）循环左移 shift 位
def left_rotate(value, shift, bits):
    return ((value << shift) | (value >> (bits - shift))) & ((1 << bits) - 1)

# --- 生成 16 个轮密钥 ---
def generate_round_keys(key):
    # 使用 PC1 将 64 位密钥置换为 56 位
    permuted_key = permute(key, PC1, 56, 64)
    # 分为左右各 28 位
    C = (permuted_key >> 28) & 0x0FFFFFFF
    D = permuted_key & 0x0FFFFFFF
    round_keys = []
    for shift in SHIFTS:
        C = left_rotate(C, shift, 28)
        D = left_rotate(D, shift, 28)
        combined = (C << 28) | D  # 56 位
        rk = permute(combined, PC2, 48, 56)
        round_keys.append(rk)
    return round_keys

# --- DES f 函数 ---
def des_f(R, round_key):
    # 扩展 R 为 48 位
    expanded_R = permute(R, E, 48, 32)
    x = expanded_R ^ round_key
    output = 0
    for i in range(8):
        shift = 42 - 6 * i
        six_bits = (x >> shift) & 0x3F
        row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01)
        col = (six_bits >> 1) & 0x0F
        s_val = S[i][row * 16 + col]
        output = (output << 4) | s_val
    f_result = permute(output, P, 32, 32)
    return f_result

# --- DES 加密 ---
def des_encrypt_block(block, key):
    round_keys = generate_round_keys(key)
    permuted_block = permute(block, IP, 64, 64)
    L = (permuted_block >> 32) & 0xFFFFFFFF
    R = permuted_block & 0xFFFFFFFF
    for rk in round_keys:
        L, R = R, L ^ des_f(R, rk)
    preoutput = (R << 32) | L
    cipher = permute(preoutput, FP, 64, 64)
    return cipher

# --- DES 解密（轮密钥逆序）---
def des_decrypt_block(block, key):
    round_keys = generate_round_keys(key)
    permuted_block = permute(block, IP, 64, 64)
    L = (permuted_block >> 32) & 0xFFFFFFFF
    R = permuted_block & 0xFFFFFFFF
    for rk in reversed(round_keys):
        L, R = R, L ^ des_f(R, rk)
    preoutput = (R << 32) | L
    plain = permute(preoutput, FP, 64, 64)
    return plain

def main():
    # 示例明文与密钥（64 位，使用十六进制表示）
    plaintext = 0x0123456789ABCDEF
    key = 0x133457799BBCDFF1
    cipher = des_encrypt_block(plaintext, key)
    decrypted = des_decrypt_block(cipher, key)
    print("明文:      %016X" % plaintext)
    print("加密后:    %016X" % cipher)
    print("解密后:    %016X" % decrypted)

if __name__ == "__main__":
    main()
```

### 3DES

代码有问题先跳了，原理就是使用3个key对明文进行加密解密再加密，解的时候反过来就行

### SM4

还有+iv、CBC等

```c
#include <stdio.h>
#include <stdint.h>

// SM4 S-盒
static const uint8_t SM4_Sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7, 0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3, 0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a, 0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95, 0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba, 0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b, 0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2, 0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52, 0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5, 0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55, 0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60, 0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f, 0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f, 0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd, 0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e, 0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20, 0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// 循环左移 32 位整数
static inline uint32_t ROTL(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// τ 变换：对 32 位字按字节做 S-盒替换
static uint32_t sm4_tau(uint32_t A) {
    return ((uint32_t)SM4_Sbox[(A >> 24) & 0xFF] << 24) |
           ((uint32_t)SM4_Sbox[(A >> 16) & 0xFF] << 16) |
           ((uint32_t)SM4_Sbox[(A >> 8) & 0xFF] << 8) |
           ((uint32_t)SM4_Sbox[A & 0xFF]);
}

// 线性变换 L（加密/解密中使用）
static uint32_t sm4_L(uint32_t B) {
    return B ^ ROTL(B,2) ^ ROTL(B,10) ^ ROTL(B,18) ^ ROTL(B,24);
}

// 线性变换 L'（密钥扩展中使用）
static uint32_t sm4_L_key(uint32_t B) {
    return B ^ ROTL(B,13) ^ ROTL(B,23);
}

// 生成 32 个轮密钥，MK 为 128 位主密钥（4 个 32 位整数），rk 输出 32 个 32 位轮密钥
void sm4_key_schedule(const uint32_t MK[4], uint32_t rk[32]) {
    static const uint32_t FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};
    static const uint32_t CK[32] = {
        0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
        0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
        0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
        0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
        0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
        0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
        0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
        0x10171e25,0x2c333a41,0x484f565d,0x646b7279
    };
    uint32_t K[36];
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; i++) {
        uint32_t temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
        uint32_t t = sm4_tau(temp);
        uint32_t L_prime = sm4_L_key(t);
        K[i+4] = K[i] ^ L_prime;
        rk[i] = K[i+4];
    }
}

// SM4 加密：对 128 位数据块 input（4 个 32 位整数）加密，输出 128 位密文 output
void sm4_encrypt_block(const uint32_t input[4], uint32_t output[4], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = input[i];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t temp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i];
        uint32_t t = sm4_tau(temp);
        uint32_t L = sm4_L(t);
        X[i+4] = X[i] ^ L;
    }
    // 输出顺序反转
    output[0] = X[35];
    output[1] = X[34];
    output[2] = X[33];
    output[3] = X[32];
}

// SM4 解密：同加密，只是轮密钥逆序使用
void sm4_decrypt_block(const uint32_t input[4], uint32_t output[4], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = input[i];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t temp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[31 - i];
        uint32_t t = sm4_tau(temp);
        uint32_t L = sm4_L(t);
        X[i+4] = X[i] ^ L;
    }
    output[0] = X[35];
    output[1] = X[34];
    output[2] = X[33];
    output[3] = X[32];
}

// 示例主函数
int main() {
    // 示例 16 字节明文与密钥（分别用 4 个 32 位整数表示）
    uint32_t plaintext[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
    uint32_t key[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
    uint32_t rk[32];
    uint32_t ciphertext[4], decrypted[4];

    sm4_key_schedule(key, rk);
    sm4_encrypt_block(plaintext, ciphertext, rk);
    sm4_decrypt_block(ciphertext, decrypted, rk);

    printf("明文:      ");
    for (int i = 0; i < 4; i++) {
        printf("%08X ", plaintext[i]);
    }
    printf("\n加密后:    ");
    for (int i = 0; i < 4; i++) {
        printf("%08X ", ciphertext[i]);
    }
    printf("\n解密后:    ");
    for (int i = 0; i < 4; i++) {
        printf("%08X ", decrypted[i]);
    }
    printf("\n");
    return 0;
}
```

```python
#!/usr/bin/env python3

# SM4 S-盒
SM4_Sbox = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7, 0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3, 0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a, 0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95, 0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba, 0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b, 0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2, 0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52, 0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5, 0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55, 0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60, 0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f, 0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f, 0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd, 0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e, 0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20, 0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
]

def ROTL(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

# τ 变换：对 32 位字按字节用 S-盒替换
def sm4_tau(A):
    return ((SM4_Sbox[(A >> 24) & 0xFF] << 24) |
            (SM4_Sbox[(A >> 16) & 0xFF] << 16) |
            (SM4_Sbox[(A >> 8) & 0xFF] << 8) |
            (SM4_Sbox[A & 0xFF]))

# 线性变换 L，用于加解密
def sm4_L(B):
    return B ^ ROTL(B,2) ^ ROTL(B,10) ^ ROTL(B,18) ^ ROTL(B,24)

# 线性变换 L'，用于密钥扩展
def sm4_L_key(B):
    return B ^ ROTL(B,13) ^ ROTL(B,23)

# 生成 32 个轮密钥，MK 为 4 个 32 位整数
def sm4_key_schedule(MK):
    FK = [0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc]
    CK = [
        0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
        0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
        0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
        0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
        0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
        0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
        0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
        0x10171e25,0x2c333a41,0x484f565d,0x646b7279
    ]
    K = [0]*36
    rk = [0]*32
    K[0] = MK[0] ^ FK[0]
    K[1] = MK[1] ^ FK[1]
    K[2] = MK[2] ^ FK[2]
    K[3] = MK[3] ^ FK[3]
    for i in range(32):
        temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]
        t = sm4_tau(temp)
        L_prime = sm4_L_key(t)
        K[i+4] = K[i] ^ L_prime
        rk[i] = K[i+4]
    return rk

# SM4 加密：对 128 位数据块（4 个 32 位整数）加密
def sm4_encrypt_block(input_block, rk):
    X = list(input_block)
    for i in range(32):
        temp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]
        t = sm4_tau(temp)
        L_val = sm4_L(t)
        X.append(X[i] ^ L_val)
    # 输出顺序反转
    return [X[35], X[34], X[33], X[32]]

# SM4 解密：使用轮密钥逆序
def sm4_decrypt_block(input_block, rk):
    X = list(input_block)
    for i in range(32):
        temp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[31 - i]
        t = sm4_tau(temp)
        L_val = sm4_L(t)
        X.append(X[i] ^ L_val)
    return [X[35], X[34], X[33], X[32]]

def main():
    # 示例 128 位明文与密钥（4 个 32 位整数表示）
    plaintext = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]
    key = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]
    rk = sm4_key_schedule(key)
    ciphertext = sm4_encrypt_block(plaintext, rk)
    decrypted = sm4_decrypt_block(ciphertext, rk)
    print("明文:     ", " ".join(f"{x:08X}" for x in plaintext))
    print("加密后:   ", " ".join(f"{x:08X}" for x in ciphertext))
    print("解密后:   ", " ".join(f"{x:08X}" for x in decrypted))

if __name__ == "__main__":
    main()
```

### blowfish

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Blowfish 上下文结构，保存 18 个 P 值和 4 个 S 盒 */
typedef struct {
    uint32_t P[18];
    uint32_t S[4][256];
} BLOWFISH_CTX;

/* Blowfish 预定义常量（取自 Bruce Schneier 的原始规格） */
static const uint32_t ORIG_P[18] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B
};

static const uint32_t ORIG_S[4][256] = {
    {
      0xD1310BA6,0x98DFB5AC,0x2FFD72DB,0xD01ADFB7,
      0xB8E1AFED,0x6A267E96,0xBA7C9045,0xF12C7F99,
      0x24A19947,0xB3916CF7,0x0801F2E2,0x858EFC16,
      0x636920D8,0x71574E69,0xA458FEA3,0xF4933D7E,
      0x0D95748F,0x728EB658,0x718BCD58,0x82154AEE,
      0x7B54A41D,0xC25A59B5,0x9C30D539,0x2AF26013,
      0xC5D1B023,0x286085F0,0xCA417918,0xB8DB38EF,
      0x8E79DCB0,0x603A180E,0x6C9E0E8B,0xB01E8A3E,
      0xD71577C1,0xBD314B27,0x78AF2FDA,0x55605C60,
      0xE65525F3,0xAA55AB94,0x57489862,0x63E81440,
      0x55CA396A,0x2AAB10B6,0xB4CC5C34,0x1141E8CE,
      0xA15486AF,0x7C72E993,0xB3EE1411,0x636FBC2A,
      0x2BA9C55D,0x741831F6,0xCE5C3E16,0x9B87931E,
      0xAFD6BA33,0x6C24CF5C,0x7A325381,0x28958677,
      0x3B8F4898,0x6B4BB9AF,0xC4BFE81B,0x66282193,
      0x61D809CC,0xFB21A991,0x487CAC60,0x5DEC8032,
      0xEF845D5D,0xE98575B1,0xDC262302,0xEB651B88,
      0x23893E81,0xD396ACC5,0x0F6D6FF3,0x83F44239,
      0x2E0B4482,0xA4842004,0x69C8F04A,0x9E1F9B5E,
      0x21C66842,0xF6E96C9A,0x670C9C61,0xABD388F0,
      0x6A51A0D2,0xD8542F68,0x960FA728,0xAB5133A3,
      0x6EEF0B6C,0x137A3BE4,0xBA3BF050,0x7EFB2A98,
      0xA1F1651D,0x39AF0176,0x66CA593E,0x82430E88,
      0x8CEE8619,0x456F9FB4,0x7D84A5C3,0x3B8B5EBE,
      0xE06F75D8,0x85C12073,0x401A449F,0x56C16AA6,
      0x4ED3AA62,0x363F7706,0x1BFEDF72,0x429B023D,
      0x37D0D724,0xD00A1248,0xDB0FEAD3,0x49F1C09B,
      0x075372C9,0x80991B7B,0x25D479D8,0xF6E8DEF7,
      0xE3FE501A,0xB6794C3B,0x976CE0BD,0x04C006BA,
      0xC1A94FB6,0x409F60C4,0x5E5C9EC2,0x196A2463,
      0x68FB6FAF,0x3E6C53B5,0x1339B2EB,0x3B52EC6F,
      0x6DFC511F,0x9B30952C,0xCC814544,0xAF5EBD09,
      0xBEE3D004,0xDE334AFD,0x660F2807,0x192E4BB3,
      0xC0CBA857,0x45C8740F,0xD20B5F39,0xB9D3FBDB,
      0x5579C0BD,0x1A60320A,0xD6A100C6,0x402C7279,
      0x679F25FE,0xFB1FA3CC,0x8EA5E9F8,0xDB3222F8,
      0x3C7516DF,0xFD616B15,0x2F501EC8,0xAD0552AB,
      0x323DB5FA,0xFD238760,0x53317B48,0x3E00DF82,
      0x9E5C57BB,0xCA6F8CA0,0x1A87562E,0xDF1769DB,
      0xD542A8F6,0x287EFFC3,0xAC6732C6,0x8C4F5573,
      0x695B27B0,0xBBCA58C8,0xE1FFA35D,0xB8F011A0,
      0x10FA3D98,0xFD2183B8,0x4AFCB56C,0x2DD1D35B,
      0x9A53E479,0xB6F84565,0xD28E49BC,0x4BFB9790,
      0xE1DDF2DA,0xA4CB7E33,0x62FB1341,0xCEE4C6E8,
      0xEF20CADA,0x36774C01,0xD07E9EFE,0x2BF11FB4,
      0x95DBDA4D,0xAE909198,0xEAAD8E71,0x6B93D5A0,
      0xD08ED1D0,0xAFC725E0,0x8E3C5B2F,0x8E7594B7,
      0x8FF6E2FB,0xF2122B64,0x8888B812,0x900DF01C,
      0x4FAD5EA0,0x688FC31C,0xD1CFF191,0xB3A8C1AD,
      0x2F2F2218,0xBE0E1777,0xEA752DFE,0x8B021FA1,
      0xE5A0CC0F,0xB56F74E8,0x18ACF3D6,0xCE89E299,
      0xB4A84FE0,0xFD13E0B7,0x7CC43B81,0xD2ADA8D9,
      0x165FA266,0x80957705,0x93CC7314,0x211A1477,
      0xE6AD2065,0x77B5FA86,0xC75442F5,0xFB9D35CF,
      0xEBCDAF0C,0x7B3E89A0,0xD6411BD3,0xAE1E7E49,
      0x00250E2D,0x2071B35E,0x226800BB,0x57B8E0AF,
      0x2464369B,0xF009B91E,0x5563911D,0x59DFA6AA,
      0x78C14389,0xD95A537F,0x207D5BA2,0x02E5B9C5,
      0x83260376,0x6295CFA9,0x11C81968,0x4E734A41,
      0xB3472DCA,0x7B14A94A,0x1B510052,0x9A532915,
      0xD60F573F,0xBC9BC6E4,0x2B60A476,0x81E67400,
      0x08BA6FB5,0x571BE91F,0xF296EC6B,0x2A0DD915,
      0xB6636521,0xE7B9F9B6,0xFF34052E,0xC5855664,
      0x53B02D5D,0xA99F8FA1,0x08BA4799,0x6E85076A
    },
    {
      0x4B7A70E9,0xB5B32944,0xDB75092E,0xC4192623,
      0xAD6EA6B0,0x49A7DF7D,0x9CEE60B8,0x8FEDB266,
      0xECAA8C71,0x699A17FF,0x5664526C,0xC2B19EE1,
      0x193602A5,0x75094C29,0xA0591340,0xE4183A3E,
      0x3F54989A,0x5B429D65,0x6B8FE4D6,0x99F73FD6,
      0xA1D29C07,0xEFE830F5,0x4D2D38E6,0xF0255DC1,
      0x4CDD2086,0x8470EB26,0x6382E9C6,0x021ECC5E,
      0x09686B3F,0x3EBAEFC9,0x3C971814,0x6B6A70A1,
      0x687F3584,0x52A0E286,0xB79C5305,0xAA500737,
      0x3E07841C,0x7FDEAE5C,0x8E7D44EC,0x5716F2B8,
      0xB03ADA37,0xF0500C0D,0xF01C1F04,0x0200B3FF,
      0xAE0CF51A,0x3CB574B2,0x25837A58,0xDC0921BD,
      0xD19113F9,0x7CA92FF6,0x94324773,0x22F54701,
      0x3AE5E581,0x37C2DADC,0xC8B57634,0x9AF3DDA7,
      0xA9446146,0x0FD0030E,0xECC8C73E,0xA4751E41,
      0xE238CD99,0x3BEA0E2F,0x3280BBA1,0x183EB331,
      0x4E548B38,0x4F6DB908,0x6F420D03,0xF60A04BF,
      0x2CB81290,0x24977C79,0x5679B072,0xBCAF89AF,
      0xDE9A771F,0xD9930810,0xB38BAE12,0xDCCF3F2E,
      0x5512721F,0x2E6B7124,0x501ADDE6,0x9F84CD87,
      0x7A584718,0x7408DA17,0xBC9F9ABC,0xE94B7D8C,
      0xEC7AEC3A,0xDB851DFA,0x63094366,0xC464C3D2,
      0xEF1C1847,0x3215D908,0xDD433B37,0x24C2BA16,
      0x12A14D43,0x2A65C451,0x50940002,0x133AE4DD,
      0x71DFF89E,0x10314E55,0x81AC77D6,0x5F11199B,
      0x043556F1,0xD7A3C76B,0x3C11183B,0x5924A509,
      0xF28FE6ED,0x97F1FBFA,0x9EBABF2C,0x1E153C6E,
      0x86E34570,0xEAE96FB1,0x860E5E0A,0x5A3E2AB3,
      0x771FE71C,0x4E3D06FA,0x2965DCB9,0x99E71D0F,
      0x803E89D6,0x5266C825,0x2E4CC978,0x9C10B36A,
      0xC6150EBA,0x94E2EA78,0xA5FC3C53,0x1E0A2DF4,
      0xF2F74EA7,0x361D2B3D,0x1939260F,0x19C27960,
      0x5223A708,0xF71312B6,0xEBADFE6E,0xEAC31F66,
      0xE3BC4595,0xA67BC883,0xB17F37D1,0x018CFF28,
      0xC332DDEF,0xBE6C5AA5,0x65582185,0x68AB9802,
      0xEECEA50F,0xDB2F953B,0x2AEF7DAD,0x5B6E2F84,
      0x1521B628,0x29076170,0xECDD4775,0x619F1510,
      0x13CCA830,0xEB61BD96,0x0334FE1E,0xAA0363CF,
      0xB5735C90,0x4C70A239,0xD59E9E0B,0xCBAADE14,
      0xEECC86BC,0x60622CA7,0x9CAB5CAB,0xB2F3846E,
      0x648B1EAF,0x19BDF0CA,0xA02369B9,0x655ABB50,
      0x40685A32,0x3C2AB4B3,0x319EE9D5,0xC021B8F7,
      0x9B540B19,0x875FA099,0x95F7997E,0x623D7DA8,
      0xF837889A,0x97E32D77,0x11ED935F,0x16681281,
      0x0E358829,0xC7E61FD6,0x96DEDFA1,0x7858BA99,
      0x57F584A5,0x1B227263,0x9B83C3FF,0x1AC24696,
      0xCDB30AEB,0x532E3054,0x8FD948E4,0x6DBC3128,
      0x58EBF2EF,0x34C6FFEA,0xFE28ED61,0xEE7C3C73,
      0x5D4A14D9,0xE864B7E3,0x42105D14,0x203E13E0,
      0x45EEE2B6,0xA3AAABEA,0xDB6C4F15,0xFACB4FD0,
      0xC742F442,0xEF6ABBB5,0x654F3B1D,0x41CD2105,
      0xD81E799E,0x86854DC7,0xE44B476A,0x3D816250,
      0xCF62A1F2,0x5B8D2646,0xFC8883A0,0xC1C7B6A3,
      0x7F1524C3,0x69CB7492,0x47848A0B,0x5692B285,
      0x095BBF00,0xAD19489D,0x1462B174,0x23820E00,
      0x58428D2A,0x0C55F5EA,0x1DADF43E,0x233F7061,
      0x3372F092,0x8D937E41,0xD65FECF1,0x6C223BDB,
      0x7CDE3759,0xCBEE7460,0x4085F2A7,0xCE77326E,
      0xA6078084,0x19F8509E,0xE8EFD855,0x61D99735,
      0xA969A7AA,0xC50C06C2,0x5A04ABFC,0x800BCADC,
      0x9E447A2E,0xC3453484,0xFDD56705,0x0E1E9EC9,
      0xDB73DBD3,0x105588CD,0x675FDA79,0xE3674340,
      0xC5C43465,0x713E38D8,0x3D28F89E,0xF16DFF20,
      0x153E21E7,0x8FB03D4A,0xE6E39F2B,0xDB83ADF7
    },
    {
      0xE93D5A68,0x948140F7,0xF64C261C,0x94692934,
      0x411520F7,0x7602D4F7,0xBCF46B2E,0xD4A20068,
      0xD4082471,0x3320F46A,0x43B7D4B7,0x500061AF,
      0x1E39F62E,0x97244546,0x14214F74,0xBF8B8840,
      0x4D95FC1D,0x96B591AF,0x70F4DDD3,0x66A02F45,
      0xBFBC09EC,0x03BD9785,0x7FAC6DD0,0x31CB8504,
      0x96EB27B3,0x55FD3941,0xDA2547E6,0xABCA0A9A,
      0x28507825,0x530429F4,0x0A2C86DA,0xE9B66DFB,
      0x68DC1462,0xD7486900,0x680EC0A4,0x27A18DEE,
      0x4F3FFEA2,0xE887AD8C,0xB58CE006,0x7AF4D6B6,
      0xAACE1E7C,0xD3375FEC,0xCE78A399,0x406B2A42,
      0x20FE9E35,0xD9F385B9,0xEE39D7AB,0x3B124E8B,
      0x1DC9FAF7,0x4B6D1856,0x26A36631,0xEAE397B2,
      0x3A6EFA74,0xDD5B4332,0x6841E7F7,0xCA7820FB,
      0xFB0AF54E,0xD8FEB397,0x454056AC,0xBA489527,
      0x55533A3A,0x20838D87,0xFE6BA9B7,0xD096954B,
      0x55A867BC,0xA1159A58,0xCCA92963,0x99E1DB33,
      0xA62A4A56,0x3F3125F9,0x5EF47E1C,0x9029317C,
      0xFDF8E802,0x04272F70,0x80BB155C,0x05282CE3,
      0x95C11548,0xE4C66D22,0x48C1133F,0xC70F86DC,
      0x07F9C9EE,0x41041F0F,0x404779A4,0x5D886E17,
      0x325F51EB,0xD59BC0D1,0xF2BCC18F,0x41113564,
      0x257B7834,0x602A9C60,0xDFF8E8A3,0x1F636C1B,
      0x0E12B4C2,0x02E1329E,0xAF664FD1,0xCAD18115,
      0x6B2395E0,0x333E92E1,0x3B240B62,0xEEBEB922,
      0x85B2A20E,0xE6BA0D99,0xDE720C8C,0x2DA2F728,
      0xD0127845,0x95B794FD,0x647D0862,0xE7CCF5F0,
      0x5449A36F,0x877D48FA,0xC39DFD27,0xF33E8D1E,
      0x0A476341,0x992EFF74,0x3A6F6EAB,0xF4F8FD37,
      0xA812DC60,0xA1EBDDF8,0x991BE14C,0xDB6E6B0D,
      0xC67B5510,0x6D672C37,0x2765D43B,0xDCD0E804,
      0xF1290DC7,0xCC00FFA3,0xB5390F92,0x690FED0B,
      0x667B9FFB,0xCEDB7D9C,0xA091CF0B,0xD9155EA3,
      0xBB132F88,0x515BAD24,0x7B9479BF,0x763BD6EB,
      0x37392EB3,0xCC115979,0x8026E297,0xF42E312D,
      0x6842ADA7,0xC66A2B3B,0x12754CCC,0x782EF11C,
      0x6A124237,0xB79251E7,0x06A1BBE6,0x4BFB6350,
      0x1A6B1018,0x11CAEDFA,0x3D25BDD8,0xE2E1C3C9,
      0x44421659,0x0A121386,0xD90CEC6E,0xD5ABEA2A,
      0x64AF674E,0xDA86A85F,0xBEBFE988,0x64E4C3FE,
      0x9DBC8057,0xF0F7C086,0x60787BF8,0x6003604D,
      0xD1FD8346,0xF6381FB0,0x7745AE04,0xD736FCCC,
      0x83426B33,0xF01EAB71,0xB0804187,0x3C005E5F,
      0x77A057BE,0xBDE8AE24,0x55464299,0xBF582E61,
      0x4E58F48F,0xF2DDFDA2,0xF474EF38,0x8789BDC2,
      0x5366F9C3,0xC8B38E74,0xB475F255,0x46FCD9B9,
      0x7AEB2661,0x8B1DDF84,0x846A0E79,0x915F95E2,
      0x466E598E,0x20B45770,0x8CD55591,0xC902DE4C,
      0xB90BACE1,0xBB8205D0,0x11A86248,0x7574A99E,
      0xB77F19B6,0xE0A9DC09,0x662D09A1,0xC4324633,
      0xE85A1F02,0x09F0BE8C,0x4A99A025,0x1D6EFE10,
      0x1AB93D1D,0x0BA5A4DF,0xA186F20F,0x2868F169,
      0xDCB7DA83,0x573906FE,0xA1E2CE9B,0x4FCD7F52,
      0x50115E01,0xA70683FA,0xA002B5C4,0x0DE6D027,
      0x9AF88C27,0x773F8641,0xC3604C06,0x61A806B5,
      0xF0177A28,0xC0F586E0,0x006058AA,0x30DC7D62,
      0x11E69ED7,0x2338EA63,0x53C2DD94,0xC2C21634,
      0xBBCBEE56,0x90BCB6DE,0xEBFC7DA1,0xCE591D76,
      0x6F05E409,0x4B7C0188,0x39720A3D,0x7C927C24,
      0x86E3725F,0x724D9DB9,0x1AC15BB4,0xD39EB8FC,
      0xED545578,0x08FCA5B5,0xD83D7CD3,0x4DAD0FC4,
      0x1E50EF5E,0xB161E6F8,0xA28514D9,0x6C51133C,
      0x6FD5C7E7,0x56E14EC4,0x362ABFCE,0xDDC6C837,
      0xD79A3234,0x92638212,0x670EFA8E,0x406000E0
    },
    {
      0x3A39CE37,0xD3FAF5CF,0xABC27737,0x5AC52D1B,
      0x5CB0679E,0x4FA33742,0xD3822740,0x99BC9BBE,
      0xD5118E9D,0xBF0F7315,0xD62D1C7E,0xC700C47B,
      0xB78C1B6B,0x21A19045,0xB26EB1BE,0x6A366EB4,
      0x5748AB2F,0xBC946E79,0xC6A376D2,0x6549C2C8,
      0x530FF8EE,0x468DDE7D,0xD5730A1D,0x4CD04DC6,
      0x2939BBDB,0xA9BA4650,0xAC9526E8,0xBE5EE304,
      0xA1FAD5F0,0x6A2D519A,0x63EF8CE2,0x9A86EE22,
      0xC089C2B8,0x43242EF6,0xA51E03AA,0x9CF2D0A4,
      0x83C061BA,0x9BE96A4D,0x8FE51550,0xBA645BD6,
      0x2826A2F9,0xA73A3AE1,0x4BA99586,0xEF5562E9,
      0xC72FEFD3,0xF752F7DA,0x3F046F69,0x77FA0A59,
      0x80E4A915,0x87B08601,0x9B09E6AD,0x3B3EE593,
      0xE990FD5A,0x9E34D797,0x2CF0B7D9,0x022B8B51,
      0x96D5AC3A,0x017DA67D,0xD1CF3ED6,0x7C7D2D28,
      0x1F9F25CF,0xADF2B89B,0x5AD6B472,0x5A88F54C,
      0xE029AC71,0xE019A5E6,0x47B0ACFD,0xED93FA9B,
      0xE8D3C48D,0x283B57CC,0xF8D56629,0x79132E28,
      0x785F0191,0xED756055,0xF7960E44,0xE3D35E8C,
      0x15056DD4,0x88F46DBA,0x03A16125,0x0564F0BD,
      0xC3EB9E15,0x3C9057A2,0x97271AEC,0xA93A072A,
      0x1B3F6D9B,0x1E6321F5,0xF59C66FB,0x26DCF319,
      0x7533D928,0xB155FDF5,0x03563482,0x8ABA3CBB,
      0x28517711,0xC20AD9F8,0xABCC5167,0xCCAD925F,
      0x4DE81751,0x3830DC8E,0x379D5862,0x9320F991,
      0xEA7A90C2,0xFB3E7BCE,0x5121CE64,0x774FBE32,
      0xA8B6E37E,0xC3293D46,0x48DE5369,0x6413E680,
      0xA2AE0810,0xDD6DB224,0x69852DFD,0x09072166,
      0xB39A460A,0x6445C0DD,0x586CDECF,0x1C20C8AE,
      0x5BBEF7DD,0x1B588D40,0xCCD2017F,0x6BB4E3BB,
      0xDDA26A7E,0x3A59FF45,0x3E350A44,0xBCB4CDD5,
      0x72EACEA8,0xFA6484BB,0x8D6612AE,0xBF3C6F47,
      0xD29BE463,0x542F5D9E,0xAEC2771B,0xF64E6370,
      0x740E0D8D,0xE75B1357,0xF8721671,0xAF537D5D,
      0x4040CB08,0x4EB4E2CC,0x34D2466A,0x0115AF84,
      0xE1B00428,0x95983A1D,0x06B89FB4,0xCE6EA048,
      0x6F3F3B82,0x3520AB82,0x011A1D4B,0x277227F8,
      0x611560B1,0xE7933FDC,0xBB3A792B,0x344525BD,
      0xA08839E1,0x51CE794B,0x2F32C9B7,0xA01FBAC9,
      0xE01CC87E,0xBCC7D1F6,0xCF0111C3,0xA1E8AAC7,
      0x1A908749,0xD44FBD9A,0xD0DADECB,0xD50ADA38,
      0x0339C32A,0xC6913667,0x8DF9317C,0xE0B12B4F,
      0xF79E59B7,0x43F5BB3A,0xF2D519FF,0x27D9459C,
      0xBF97222C,0x15E6FC2A,0x0F91FC71,0x9B941525,
      0xFAE59361,0xCEB69CEB,0xC2A86459,0x12BAA8D1,
      0xB6C1075E,0xE3056A0C,0x10D25065,0xCB03A442,
      0xE0EC6E0E,0x1698DB3B,0x4C98A0BE,0x3278E964,
      0x9F1F9532,0xE0D392DF,0xD3A0342B,0x8971F21E,
      0x1B0A7441,0x4BA3348C,0xC5BE7120,0xC37632D8,
      0xDF359F8D,0x9B992F2E,0xE60B6F47,0x0FE3F11D,
      0xE54CDA54,0x1EDAD891,0xCE6279CF,0xCD3E7E6F,
      0x1618B166,0xFD2C1D05,0x848FD2C5,0xF6FB2299,
      0xF523F357,0xA6327623,0x93A83531,0x56CCCD02,
      0xACF08162,0x5A75EBB5,0x6E163697,0x88D273CC,
      0xDE966292,0x81B949D0,0x4C50901B,0x71C65614,
      0xE6C6C7BD,0x327A140A,0x45E1D006,0xC3F27B9A,
      0xC9AA53FD,0x62A80F00,0xBB25BFE2,0x35BDD2F6,
      0x71126905,0xB2040222,0xB6CBCF7C,0xCD769C2B,
      0x53113EC0,0x1640E3D3,0x38ABBD60,0x2547ADF0,
      0xBA38209C,0xF746CE76,0x77AFA1C5,0x20756060,
      0x85CBFE4E,0x8AE88DD8,0x7AAAF9B0,0x4CF9AA7E,
      0x1948C25C,0x02FB8A8C,0x01C36AE4,0xD6EBE1F9,
      0x90D4F869,0xA65CDEA0,0x3F09252D,0xC208E69F,
      0xB74E6132,0xCE77E25B,0x578FDFE3,0x3AC372E6
    }
};

/* F 函数：将 32 位输入分解为 4 字节，经 S 盒及加法、异或组合后返回 32 位结果 */
static uint32_t Blowfish_F(BLOWFISH_CTX *ctx, uint32_t x) {
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >> 8)  & 0xFF;
    uint8_t d = x & 0xFF;
    return (((ctx->S[0][a] + ctx->S[1][b]) ^ ctx->S[2][c]) + ctx->S[3][d]);
}

/* 加密 64 位块（L,R 分别为左右 32 位） */
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, uint32_t *L, uint32_t *R) {
    uint32_t l = *L, r = *R;
    int i;
    for(i = 0; i < 16; i++){
        l ^= ctx->P[i];
        r ^= Blowfish_F(ctx, l);
        // 交换 l 和 r
        uint32_t temp = l;
        l = r;
        r = temp;
    }
    // 交换回
    uint32_t temp = l;
    l = r;
    r = temp;
    r ^= ctx->P[16];
    l ^= ctx->P[17];
    *L = l;
    *R = r;
}

/* 解密 64 位块（使用逆序的 P 数组） */
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, uint32_t *L, uint32_t *R) {
    uint32_t l = *L, r = *R;
    int i;
    for(i = 17; i > 1; i--){
        l ^= ctx->P[i];
        r ^= Blowfish_F(ctx, l);
        uint32_t temp = l;
        l = r;
        r = temp;
    }
    uint32_t temp = l;
    l = r;
    r = temp;
    r ^= ctx->P[1];
    l ^= ctx->P[0];
    *L = l;
    *R = r;
}

/* Blowfish 密钥扩展：将 key（keyLen 字节）混入 P 数组，再用 0 块反复加密更新 P 和 S */
void Blowfish_Init(BLOWFISH_CTX *ctx, const uint8_t *key, int keyLen) {
    int i, j, k;
    // 复制初始 P 和 S 常量
    memcpy(ctx->P, ORIG_P, sizeof(ORIG_P));
    memcpy(ctx->S, ORIG_S, sizeof(ORIG_S));
    j = 0;
    for(i = 0; i < 18; i++){
        uint32_t data = 0;
        for(k = 0; k < 4; k++){
            data = (data << 8) | key[j];
            j = (j + 1) % keyLen;
        }
        ctx->P[i] ^= data;
    }
    uint32_t L = 0, R = 0;
    for(i = 0; i < 18; i += 2){
        Blowfish_Encrypt(ctx, &L, &R);
        ctx->P[i] = L;
        ctx->P[i+1] = R;
    }
    for(i = 0; i < 4; i++){
        for(j = 0; j < 256; j += 2){
            Blowfish_Encrypt(ctx, &L, &R);
            ctx->S[i][j] = L;
            ctx->S[i][j+1] = R;
        }
    }
}

/* 示例主函数 */
int main() {
    BLOWFISH_CTX ctx;
    /* 示例密钥及明文（8 字节） */
    const uint8_t key[] = "BlowfishKey";  // 任意长度
    uint32_t L = 0x01234567, R = 0x89ABCDEF;
    printf("原始明文: %08X %08X\n", L, R);
    
    Blowfish_Init(&ctx, key, (int)strlen((const char *)key));
    Blowfish_Encrypt(&ctx, &L, &R);
    printf("加密后  : %08X %08X\n", L, R);
    
    Blowfish_Decrypt(&ctx, &L, &R);
    printf("解密后  : %08X %08X\n", L, R);
    
    return 0;
}
```

```python
#!/usr/bin/env python3
import struct

# Blowfish 预定义常量（与 C 版中 ORIG_P 和 ORIG_S 相同）
ORIG_P = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B
]

ORIG_S = [
    [
      0xD1310BA6,0x98DFB5AC,0x2FFD72DB,0xD01ADFB7,
      0xB8E1AFED,0x6A267E96,0xBA7C9045,0xF12C7F99,
      0x24A19947,0xB3916CF7,0x0801F2E2,0x858EFC16,
      0x636920D8,0x71574E69,0xA458FEA3,0xF4933D7E,
      0x0D95748F,0x728EB658,0x718BCD58,0x82154AEE,
      0x7B54A41D,0xC25A59B5,0x9C30D539,0x2AF26013,
      0xC5D1B023,0x286085F0,0xCA417918,0xB8DB38EF,
      0x8E79DCB0,0x603A180E,0x6C9E0E8B,0xB01E8A3E,
      0xD71577C1,0xBD314B27,0x78AF2FDA,0x55605C60,
      0xE65525F3,0xAA55AB94,0x57489862,0x63E81440,
      0x55CA396A,0x2AAB10B6,0xB4CC5C34,0x1141E8CE,
      0xA15486AF,0x7C72E993,0xB3EE1411,0x636FBC2A,
      0x2BA9C55D,0x741831F6,0xCE5C3E16,0x9B87931E,
      0xAFD6BA33,0x6C24CF5C,0x7A325381,0x28958677,
      0x3B8F4898,0x6B4BB9AF,0xC4BFE81B,0x66282193,
      0x61D809CC,0xFB21A991,0x487CAC60,0x5DEC8032,
      0xEF845D5D,0xE98575B1,0xDC262302,0xEB651B88,
      0x23893E81,0xD396ACC5,0x0F6D6FF3,0x83F44239,
      0x2E0B4482,0xA4842004,0x69C8F04A,0x9E1F9B5E,
      0x21C66842,0xF6E96C9A,0x670C9C61,0xABD388F0,
      0x6A51A0D2,0xD8542F68,0x960FA728,0xAB5133A3,
      0x6EEF0B6C,0x137A3BE4,0xBA3BF050,0x7EFB2A98,
      0xA1F1651D,0x39AF0176,0x66CA593E,0x82430E88,
      0x8CEE8619,0x456F9FB4,0x7D84A5C3,0x3B8B5EBE,
      0xE06F75D8,0x85C12073,0x401A449F,0x56C16AA6,
      0x4ED3AA62,0x363F7706,0x1BFEDF72,0x429B023D,
      0x37D0D724,0xD00A1248,0xDB0FEAD3,0x49F1C09B,
      0x075372C9,0x80991B7B,0x25D479D8,0xF6E8DEF7,
      0xE3FE501A,0xB6794C3B,0x976CE0BD,0x04C006BA,
      0xC1A94FB6,0x409F60C4,0x5E5C9EC2,0x196A2463,
      0x68FB6FAF,0x3E6C53B5,0x1339B2EB,0x3B52EC6F,
      0x6DFC511F,0x9B30952C,0xCC814544,0xAF5EBD09,
      0xBEE3D004,0xDE334AFD,0x660F2807,0x192E4BB3,
      0xC0CBA857,0x45C8740F,0xD20B5F39,0xB9D3FBDB,
      0x5579C0BD,0x1A60320A,0xD6A100C6,0x402C7279,
      0x679F25FE,0xFB1FA3CC,0x8EA5E9F8,0xDB3222F8,
      0x3C7516DF,0xFD616B15,0x2F501EC8,0xAD0552AB,
      0x323DB5FA,0xFD238760,0x53317B48,0x3E00DF82,
      0x9E5C57BB,0xCA6F8CA0,0x1A87562E,0xDF1769DB,
      0xD542A8F6,0x287EFFC3,0xAC6732C6,0x8C4F5573,
      0x695B27B0,0xBBCA58C8,0xE1FFA35D,0xB8F011A0,
      0x10FA3D98,0xFD2183B8,0x4AFCB56C,0x2DD1D35B,
      0x9A53E479,0xB6F84565,0xD28E49BC,0x4BFB9790,
      0xE1DDF2DA,0xA4CB7E33,0x62FB1341,0xCEE4C6E8,
      0xEF20CADA,0x36774C01,0xD07E9EFE,0x2BF11FB4,
      0x95DBDA4D,0xAE909198,0xEAAD8E71,0x6B93D5A0,
      0xD08ED1D0,0xAFC725E0,0x8E3C5B2F,0x8E7594B7,
      0x8FF6E2FB,0xF2122B64,0x8888B812,0x900DF01C,
      0x4FAD5EA0,0x688FC31C,0xD1CFF191,0xB3A8C1AD,
      0x2F2F2218,0xBE0E1777,0xEA752DFE,0x8B021FA1,
      0xE5A0CC0F,0xB56F74E8,0x18ACF3D6,0xCE89E299,
      0xB4A84FE0,0xFD13E0B7,0x7CC43B81,0xD2ADA8D9,
      0x165FA266,0x80957705,0x93CC7314,0x211A1477,
      0xE6AD2065,0x77B5FA86,0xC75442F5,0xFB9D35CF,
      0xEBCDAF0C,0x7B3E89A0,0xD6411BD3,0xAE1E7E49,
      0x00250E2D,0x2071B35E,0x226800BB,0x57B8E0AF,
      0x2464369B,0xF009B91E,0x5563911D,0x59DFA6AA,
      0x78C14389,0xD95A537F,0x207D5BA2,0x02E5B9C5,
      0x83260376,0x6295CFA9,0x11C81968,0x4E734A41,
      0xB3472DCA,0x7B14A94A,0x1B510052,0x9A532915,
      0xD60F573F,0xBC9BC6E4,0x2B60A476,0x81E67400,
      0x08BA6FB5,0x571BE91F,0xF296EC6B,0x2A0DD915,
      0xB6636521,0xE7B9F9B6,0xFF34052E,0xC5855664,
      0x53B02D5D,0xA99F8FA1,0x08BA4799,0x6E85076A
    ],
    [
      0x4B7A70E9,0xB5B32944,0xDB75092E,0xC4192623,
      0xAD6EA6B0,0x49A7DF7D,0x9CEE60B8,0x8FEDB266,
      0xECAA8C71,0x699A17FF,0x5664526C,0xC2B19EE1,
      0x193602A5,0x75094C29,0xA0591340,0xE4183A3E,
      0x3F54989A,0x5B429D65,0x6B8FE4D6,0x99F73FD6,
      0xA1D29C07,0xEFE830F5,0x4D2D38E6,0xF0255DC1,
      0x4CDD2086,0x8470EB26,0x6382E9C6,0x021ECC5E,
      0x09686B3F,0x3EBAEFC9,0x3C971814,0x6B6A70A1,
      0x687F3584,0x52A0E286,0xB79C5305,0xAA500737,
      0x3E07841C,0x7FDEAE5C,0x8E7D44EC,0x5716F2B8,
      0xB03ADA37,0xF0500C0D,0xF01C1F04,0x0200B3FF,
      0xAE0CF51A,0x3CB574B2,0x25837A58,0xDC0921BD,
      0xD19113F9,0x7CA92FF6,0x94324773,0x22F54701,
      0x3AE5E581,0x37C2DADC,0xC8B57634,0x9AF3DDA7,
      0xA9446146,0x0FD0030E,0xECC8C73E,0xA4751E41,
      0xE238CD99,0x3BEA0E2F,0x3280BBA1,0x183EB331,
      0x4E548B38,0x4F6DB908,0x6F420D03,0xF60A04BF,
      0x2CB81290,0x24977C79,0x5679B072,0xBCAF89AF,
      0xDE9A771F,0xD9930810,0xB38BAE12,0xDCCF3F2E,
      0x5512721F,0x2E6B7124,0x501ADDE6,0x9F84CD87,
      0x7A584718,0x7408DA17,0xBC9F9ABC,0xE94B7D8C,
      0xEC7AEC3A,0xDB851DFA,0x63094366,0xC464C3D2,
      0xEF1C1847,0x3215D908,0xDD433B37,0x24C2BA16,
      0x12A14D43,0x2A65C451,0x50940002,0x133AE4DD,
      0x71DFF89E,0x10314E55,0x81AC77D6,0x5F11199B,
      0x043556F1,0xD7A3C76B,0x3C11183B,0x5924A509,
      0xF28FE6ED,0x97F1FBFA,0x9EBABF2C,0x1E153C6E,
      0x86E34570,0xEAE96FB1,0x860E5E0A,0x5A3E2AB3,
      0x771FE71C,0x4E3D06FA,0x2965DCB9,0x99E71D0F,
      0x803E89D6,0x5266C825,0x2E4CC978,0x9C10B36A,
      0xC6150EBA,0x94E2EA78,0xA5FC3C53,0x1E0A2DF4,
      0xF2F74EA7,0x361D2B3D,0x1939260F,0x19C27960,
      0x5223A708,0xF71312B6,0xEBADFE6E,0xEAC31F66,
      0xE3BC4595,0xA67BC883,0xB17F37D1,0x018CFF28,
      0xC332DDEF,0xBE6C5AA5,0x65582185,0x68AB9802,
      0xEECEA50F,0xDB2F953B,0x2AEF7DAD,0x5B6E2F84,
      0x1521B628,0x29076170,0xECDD4775,0x619F1510,
      0x13CCA830,0xEB61BD96,0x0334FE1E,0xAA0363CF,
      0xB5735C90,0x4C70A239,0xD59E9E0B,0xCBAADE14,
      0xEECC86BC,0x60622CA7,0x9CAB5CAB,0xB2F3846E,
      0x648B1EAF,0x19BDF0CA,0xA02369B9,0x655ABB50,
      0x40685A32,0x3C2AB4B3,0x319EE9D5,0xC021B8F7,
      0x9B540B19,0x875FA099,0x95F7997E,0x623D7DA8,
      0xF837889A,0x97E32D77,0x11ED935F,0x16681281,
      0x0E358829,0xC7E61FD6,0x96DEDFA1,0x7858BA99,
      0x57F584A5,0x1B227263,0x9B83C3FF,0x1AC24696,
      0xCDB30AEB,0x532E3054,0x8FD948E4,0x6DBC3128,
      0x58EBF2EF,0x34C6FFEA,0xFE28ED61,0xEE7C3C73,
      0x5D4A14D9,0xE864B7E3,0x42105D14,0x203E13E0,
      0x45EEE2B6,0xA3AAABEA,0xDB6C4F15,0xFACB4FD0,
      0xC742F442,0xEF6ABBB5,0x654F3B1D,0x41CD2105,
      0xD81E799E,0x86854DC7,0xE44B476A,0x3D816250,
      0xCF62A1F2,0x5B8D2646,0xFC8883A0,0xC1C7B6A3,
      0x7F1524C3,0x69CB7492,0x47848A0B,0x5692B285,
      0x095BBF00,0xAD19489D,0x1462B174,0x23820E00,
      0x58428D2A,0x0C55F5EA,0x1DADF43E,0x233F7061,
      0x3372F092,0x8D937E41,0xD65FECF1,0x6C223BDB,
      0x7CDE3759,0xCBEE7460,0x4085F2A7,0xCE77326E,
      0xA6078084,0x19F8509E,0xE8EFD855,0x61D99735,
      0xA969A7AA,0xC50C06C2,0x5A04ABFC,0x800BCADC,
      0x9E447A2E,0xC3453484,0xFDD56705,0x0E1E9EC9,
      0xDB73DBD3,0x105588CD,0x675FDA79,0xE3674340,
      0xC5C43465,0x713E38D8,0x3D28F89E,0xF16DFF20,
      0x153E21E7,0x8FB03D4A,0xE6E39F2B,0xDB83ADF7
    ],
    [
      0xE93D5A68,0x948140F7,0xF64C261C,0x94692934,
      0x411520F7,0x7602D4F7,0xBCF46B2E,0xD4A20068,
      0xD4082471,0x3320F46A,0x43B7D4B7,0x500061AF,
      0x1E39F62E,0x97244546,0x14214F74,0xBF8B8840,
      0x4D95FC1D,0x96B591AF,0x70F4DDD3,0x66A02F45,
      0xBFBC09EC,0x03BD9785,0x7FAC6DD0,0x31CB8504,
      0x96EB27B3,0x55FD3941,0xDA2547E6,0xABCA0A9A,
      0x28507825,0x530429F4,0x0A2C86DA,0xE9B66DFB,
      0x68DC1462,0xD7486900,0x680EC0A4,0x27A18DEE,
      0x4F3FFEA2,0xE887AD8C,0xB58CE006,0x7AF4D6B6,
      0xAACE1E7C,0xD3375FEC,0xCE78A399,0x406B2A42,
      0x20FE9E35,0xD9F385B9,0xEE39D7AB,0x3B124E8B,
      0x1DC9FAF7,0x4B6D1856,0x26A36631,0xEAE397B2,
      0x3A6EFA74,0xDD5B4332,0x6841E7F7,0xCA7820FB,
      0xFB0AF54E,0xD8FEB397,0x454056AC,0xBA489527,
      0x55533A3A,0x20838D87,0xFE6BA9B7,0xD096954B,
      0x55A867BC,0xA1159A58,0xCCA92963,0x99E1DB33,
      0xA62A4A56,0x3F3125F9,0x5EF47E1C,0x9029317C,
      0xFDF8E802,0x04272F70,0x80BB155C,0x05282CE3,
      0x95C11548,0xE4C66D22,0x48C1133F,0xC70F86DC,
      0x07F9C9EE,0x41041F0F,0x404779A4,0x5D886E17,
      0x325F51EB,0xD59BC0D1,0xF2BCC18F,0x41113564,
      0x257B7834,0x602A9C60,0xDFF8E8A3,0x1F636C1B,
      0x0E12B4C2,0x02E1329E,0xAF664FD1,0xCAD18115,
      0x6B2395E0,0x333E92E1,0x3B240B62,0xEEBEB922,
      0x85B2A20E,0xE6BA0D99,0xDE720C8C,0x2DA2F728,
      0xD0127845,0x95B794FD,0x647D0862,0xE7CCF5F0,
      0x5449A36F,0x877D48FA,0xC39DFD27,0xF33E8D1E,
      0x0A476341,0x992EFF74,0x3A6F6EAB,0xF4F8FD37,
      0xA812DC60,0xA1EBDDF8,0x991BE14C,0xDB6E6B0D,
      0xC67B5510,0x6D672C37,0x2765D43B,0xDCD0E804,
      0xF1290DC7,0xCC00FFA3,0xB5390F92,0x690FED0B,
      0x667B9FFB,0xCEDB7D9C,0xA091CF0B,0xD9155EA3,
      0xBB132F88,0x515BAD24,0x7B9479BF,0x763BD6EB,
      0x37392EB3,0xCC115979,0x8026E297,0xF42E312D,
      0x6842ADA7,0xC66A2B3B,0x12754CCC,0x782EF11C,
      0x6A124237,0xB79251E7,0x06A1BBE6,0x4BFB6350,
      0x1A6B1018,0x11CAEDFA,0x3D25BDD8,0xE2E1C3C9,
      0x44421659,0x0A121386,0xD90CEC6E,0xD5ABEA2A,
      0x64AF674E,0xDA86A85F,0xBEBFE988,0x64E4C3FE,
      0x9DBC8057,0xF0F7C086,0x60787BF8,0x6003604D,
      0xD1FD8346,0xF6381FB0,0x7745AE04,0xD736FCCC,
      0x83426B33,0xF01EAB71,0xB0804187,0x3C005E5F,
      0x77A057BE,0xBDE8AE24,0x55464299,0xBF582E61,
      0x4E58F48F,0xF2DDFDA2,0xF474EF38,0x8789BDC2,
      0x5366F9C3,0xC8B38E74,0xB475F255,0x46FCD9B9,
      0x7AEB2661,0x8B1DDF84,0x846A0E79,0x915F95E2,
      0x466E598E,0x20B45770,0x8CD55591,0xC902DE4C,
      0xB90BACE1,0xBB8205D0,0x11A86248,0x7574A99E,
      0xB77F19B6,0xE0A9DC09,0x662D09A1,0xC4324633,
      0xE85A1F02,0x09F0BE8C,0x4A99A025,0x1D6EFE10,
      0x1AB93D1D,0x0BA5A4DF,0xA186F20F,0x2868F169,
      0xDCB7DA83,0x573906FE,0xA1E2CE9B,0x4FCD7F52,
      0x50115E01,0xA70683FA,0xA002B5C4,0x0DE6D027,
      0x9AF88C27,0x773F8641,0xC3604C06,0x61A806B5,
      0xF0177A28,0xC0F586E0,0x006058AA,0x30DC7D62,
      0x11E69ED7,0x2338EA63,0x53C2DD94,0xC2C21634,
      0xBBCBEE56,0x90BCB6DE,0xEBFC7DA1,0xCE591D76,
      0x6F05E409,0x4B7C0188,0x39720A3D,0x7C927C24,
      0x86E3725F,0x724D9DB9,0x1AC15BB4,0xD39EB8FC,
      0xED545578,0x08FCA5B5,0xD83D7CD3,0x4DAD0FC4,
      0x1E50EF5E,0xB161E6F8,0xA28514D9,0x6C51133C,
      0x6FD5C7E7,0x56E14EC4,0x362ABFCE,0xDDC6C837,
      0xD79A3234,0x92638212,0x670EFA8E,0x406000E0
    ],
    [
      0x3A39CE37,0xD3FAF5CF,0xABC27737,0x5AC52D1B,
      0x5CB0679E,0x4FA33742,0xD3822740,0x99BC9BBE,
      0xD5118E9D,0xBF0F7315,0xD62D1C7E,0xC700C47B,
      0xB78C1B6B,0x21A19045,0xB26EB1BE,0x6A366EB4,
      0x5748AB2F,0xBC946E79,0xC6A376D2,0x6549C2C8,
      0x530FF8EE,0x468DDE7D,0xD5730A1D,0x4CD04DC6,
      0x2939BBDB,0xA9BA4650,0xAC9526E8,0xBE5EE304,
      0xA1FAD5F0,0x6A2D519A,0x63EF8CE2,0x9A86EE22,
      0xC089C2B8,0x43242EF6,0xA51E03AA,0x9CF2D0A4,
      0x83C061BA,0x9BE96A4D,0x8FE51550,0xBA645BD6,
      0x2826A2F9,0xA73A3AE1,0x4BA99586,0xEF5562E9,
      0xC72FEFD3,0xF752F7DA,0x3F046F69,0x77FA0A59,
      0x80E4A915,0x87B08601,0x9B09E6AD,0x3B3EE593,
      0xE990FD5A,0x9E34D797,0x2CF0B7D9,0x022B8B51,
      0x96D5AC3A,0x017DA67D,0xD1CF3ED6,0x7C7D2D28,
      0x1F9F25CF,0xADF2B89B,0x5AD6B472,0x5A88F54C,
      0xE029AC71,0xE019A5E6,0x47B0ACFD,0xED93FA9B,
      0xE8D3C48D,0x283B57CC,0xF8D56629,0x79132E28,
      0x785F0191,0xED756055,0xF7960E44,0xE3D35E8C,
      0x15056DD4,0x88F46DBA,0x03A16125,0x0564F0BD,
      0xC3EB9E15,0x3C9057A2,0x97271AEC,0xA93A072A,
      0x1B3F6D9B,0x1E6321F5,0xF59C66FB,0x26DCF319,
      0x7533D928,0xB155FDF5,0x03563482,0x8ABA3CBB,
      0x28517711,0xC20AD9F8,0xABCC5167,0xCCAD925F,
      0x4DE81751,0x3830DC8E,0x379D5862,0x9320F991,
      0xEA7A90C2,0xFB3E7BCE,0x5121CE64,0x774FBE32,
      0xA8B6E37E,0xC3293D46,0x48DE5369,0x6413E680,
      0xA2AE0810,0xDD6DB224,0x69852DFD,0x09072166,
      0xB39A460A,0x6445C0DD,0x586CDECF,0x1C20C8AE,
      0x5BBEF7DD,0x1B588D40,0xCCD2017F,0x6BB4E3BB,
      0xDDA26A7E,0x3A59FF45,0x3E350A44,0xBCB4CDD5,
      0x72EACEA8,0xFA6484BB,0x8D6612AE,0xBF3C6F47,
      0xD29BE463,0x542F5D9E,0xAEC2771B,0xF64E6370,
      0x740E0D8D,0xE75B1357,0xF8721671,0xAF537D5D,
      0x4040CB08,0x4EB4E2CC,0x34D2466A,0x0115AF84,
      0xE1B00428,0x95983A1D,0x06B89FB4,0xCE6EA048,
      0x6F3F3B82,0x3520AB82,0x011A1D4B,0x277227F8,
      0x611560B1,0xE7933FDC,0xBB3A792B,0x344525BD,
      0xA08839E1,0x51CE794B,0x2F32C9B7,0xA01FBAC9,
      0xE01CC87E,0xBCC7D1F6,0xCF0111C3,0xA1E8AAC7,
      0x1A908749,0xD44FBD9A,0xD0DADECB,0xD50ADA38,
      0x0339C32A,0xC6913667,0x8DF9317C,0xE0B12B4F,
      0xF79E59B7,0x43F5BB3A,0xF2D519FF,0x27D9459C,
      0xBF97222C,0x15E6FC2A,0x0F91FC71,0x9B941525,
      0xFAE59361,0xCEB69CEB,0xC2A86459,0x12BAA8D1,
      0xB6C1075E,0xE3056A0C,0x10D25065,0xCB03A442,
      0xE0EC6E0E,0x1698DB3B,0x4C98A0BE,0x3278E964,
      0x9F1F9532,0xE0D392DF,0xD3A0342B,0x8971F21E,
      0x1B0A7441,0x4BA3348C,0xC5BE7120,0xC37632D8,
      0xDF359F8D,0x9B992F2E,0xE60B6F47,0x0FE3F11D,
      0xE54CDA54,0x1EDAD891,0xCE6279CF,0xCD3E7E6F,
      0x1618B166,0xFD2C1D05,0x848FD2C5,0xF6FB2299,
      0xF523F357,0xA6327623,0x93A83531,0x56CCCD02,
      0xACF08162,0x5A75EBB5,0x6E163697,0x88D273CC,
      0xDE966292,0x81B949D0,0x4C50901B,0x71C65614,
      0xE6C6C7BD,0x327A140A,0x45E1D006,0xC3F27B9A,
      0xC9AA53FD,0x62A80F00,0xBB25BFE2,0x35BDD2F6,
      0x71126905,0xB2040222,0xB6CBCF7C,0xCD769C2B,
      0x53113EC0,0x1640E3D3,0x38ABBD60,0x2547ADF0,
      0xBA38209C,0xF746CE76,0x77AFA1C5,0x20756060,
      0x85CBFE4E,0x8AE88DD8,0x7AAAF9B0,0x4CF9AA7E,
      0x1948C25C,0x02FB8A8C,0x01C36AE4,0xD6EBE1F9,
      0x90D4F869,0xA65CDEA0,0x3F09252D,0xC208E69F,
      0xB74E6132,0xCE77E25B,0x578FDFE3,0x3AC372E6
    ]
]

class Blowfish:
    def __init__(self, key: bytes):
        # 初始化 P 数组和 S 盒
        self.P = ORIG_P.copy()
        self.S = [sbox.copy() for sbox in ORIG_S]
        key_len = len(key)
        j = 0
        # 将 key 混入 P 数组
        for i in range(18):
            data = 0
            for k in range(4):
                data = (data << 8) | key[j]
                j = (j + 1) % key_len
            self.P[i] ^= data
        L, R = 0, 0
        # 用全 0 块不断加密更新 P 数组
        for i in range(0, 18, 2):
            L, R = self._encrypt_block(L, R)
            self.P[i] = L
            self.P[i+1] = R
        # 更新 S 盒
        for s in range(4):
            for i in range(0, 256, 2):
                L, R = self._encrypt_block(L, R)
                self.S[s][i] = L
                self.S[s][i+1] = R

    def _F(self, x: int) -> int:
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF
        return (((self.S[0][a] + self.S[1][b]) ^ self.S[2][c]) + self.S[3][d]) & 0xFFFFFFFF

    def _encrypt_block(self, L: int, R: int) -> (int, int):
        for i in range(16):
            L = L ^ self.P[i]
            R = R ^ self._F(L)
            L, R = R, L  # 交换
        L, R = R, L  # 交换回
        R = R ^ self.P[16]
        L = L ^ self.P[17]
        return L & 0xFFFFFFFF, R & 0xFFFFFFFF

    def _decrypt_block(self, L: int, R: int) -> (int, int):
        for i in range(17, 1, -1):
            L = L ^ self.P[i]
            R = R ^ self._F(L)
            L, R = R, L
        L, R = R, L
        R = R ^ self.P[1]
        L = L ^ self.P[0]
        return L & 0xFFFFFFFF, R & 0xFFFFFFFF

    def encrypt(self, block: bytes) -> bytes:
        # block 长度应为 8 字节
        L, R = struct.unpack('>II', block)
        L, R = self._encrypt_block(L, R)
        return struct.pack('>II', L, R)

    def decrypt(self, block: bytes) -> bytes:
        L, R = struct.unpack('>II', block)
        L, R = self._decrypt_block(L, R)
        return struct.pack('>II', L, R)

def main():
    key = b"BlowfishKey"
    plaintext = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
    bf = Blowfish(key)
    cipher = bf.encrypt(plaintext)
    decrypted = bf.decrypt(cipher)
    print("原始明文:", plaintext.hex().upper())
    print("加密后  :", cipher.hex().upper())
    print("解密后  :", decrypted.hex().upper())

if __name__ == "__main__":
    main()
```

### RSA

```c
#include <stdio.h>

// 计算 base^exp mod mod（快速幂算法）
unsigned long long modexp(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    base %= mod;
    while(exp > 0) {
        if(exp & 1)
            result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

int main() {
    // 示例 RSA 参数（仅供演示）
    unsigned long long n = 3233;    // 模数
    unsigned long long e = 17;      // 公钥指数
    unsigned long long d = 2753;    // 私钥指数

    unsigned long long plaintext = 65; // 示例明文（数字 65，对应字符 'A'）
    
    // 加密与解密
    unsigned long long ciphertext = modexp(plaintext, e, n);
    unsigned long long decrypted  = modexp(ciphertext, d, n);

    printf("明文:      %llu\n", plaintext);
    printf("加密后:    %llu\n", ciphertext);
    printf("解密后:    %llu\n", decrypted);

    return 0;
}
```

```python
#!/usr/bin/env python3

# RSA 加密：计算 plaintext^e mod n
def rsa_encrypt(plaintext, e, n):
    return pow(plaintext, e, n)

# RSA 解密：计算 ciphertext^d mod n
def rsa_decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)

def main():
    # 示例 RSA 参数（仅供演示）
    n = 3233    # 模数
    e = 17      # 公钥指数
    d = 2753    # 私钥指数

    plaintext = 65  # 示例明文（数字 65，对应字符 'A'）
    
    ciphertext = rsa_encrypt(plaintext, e, n)
    decrypted  = rsa_decrypt(ciphertext, d, n)

    print("明文:     ", plaintext)
    print("加密后:   ", ciphertext)
    print("解密后:   ", decrypted)

if __name__ == "__main__":
    main()
```

### Diffie-Hellman(DH)密钥交换

```c
#include <stdio.h>

// 快速求幂：计算 base^exp mod mod
unsigned long modexp(unsigned long base, unsigned long exp, unsigned long mod) {
    unsigned long result = 1;
    base %= mod;
    while(exp > 0) {
        if(exp & 1)
            result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

int main(void) {
    // 公开参数：大素数 p 和原根 g
    unsigned long p = 23;  // 素数模数
    unsigned long g = 5;   // 原根

    // 双方私钥（应随机选择，此处固定仅作演示）
    unsigned long a = 6;   // A 的私钥
    unsigned long b = 15;  // B 的私钥

    // 计算各自的公开值
    unsigned long A_pub = modexp(g, a, p);  // A 公开值：g^a mod p
    unsigned long B_pub = modexp(g, b, p);  // B 公开值：g^b mod p

    // 双方计算共享密钥
    unsigned long shared_A = modexp(B_pub, a, p);  // A 计算共享密钥：B_pub^a mod p
    unsigned long shared_B = modexp(A_pub, b, p);  // B 计算共享密钥：A_pub^b mod p

    printf("公开参数: p = %lu, g = %lu\n", p, g);
    printf("A 的私钥: %lu, 公开值: %lu\n", a, A_pub);
    printf("B 的私钥: %lu, 公开值: %lu\n", b, B_pub);
    printf("A 计算共享密钥: %lu\n", shared_A);
    printf("B 计算共享密钥: %lu\n", shared_B);

    return 0;
}
```

```python
#!/usr/bin/env python3

# 快速求幂：计算 base^exp mod mod
def modexp(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

def main():
    # 公开参数
    p = 23  # 素数
    g = 5   # 原根

    # 双方私钥（实际应用中应随机选择）
    a = 6   # A 的私钥
    b = 15  # B 的私钥

    # 计算公开值
    A_pub = modexp(g, a, p)  # A 公开值
    B_pub = modexp(g, b, p)  # B 公开值

    # 计算共享密钥
    shared_A = modexp(B_pub, a, p)
    shared_B = modexp(A_pub, b, p)

    print("公开参数: p =", p, "g =", g)
    print("A 的私钥:", a, "公开值:", A_pub)
    print("B 的私钥:", b, "公开值:", B_pub)
    print("A 计算共享密钥:", shared_A)
    print("B 计算共享密钥:", shared_B)

if __name__ == "__main__":
    main()
```

## 哈希算法

### MD5

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* MD5 上下文结构 */
typedef struct {
    uint32_t state[4];       // A, B, C, D
    uint32_t count[2];       // 消息长度（以位计数），模 2^64
    unsigned char buffer[64]; // 输入缓冲区
} MD5_CTX;

/* 函数声明 */
void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, const unsigned char *input, unsigned int inputLen);
void MD5Final(unsigned char digest[16], MD5_CTX *context);
void MD5Transform(uint32_t state[4], const unsigned char block[64]);

/* 定义 4 轮每步的移位数 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* 四个辅助函数 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* 循环左移 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* 四轮操作宏 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT((a), (s)); \
 (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT((a), (s)); \
 (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT((a), (s)); \
 (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
 (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT((a), (s)); \
 (a) += (b); \
}

/* 将输入 uint32_t 数组编码为字节数组（小端序） */
void Encode(unsigned char *output, uint32_t *input, unsigned int len) {
    unsigned int i, j;
    for(i = 0, j = 0; j < len; i++, j += 4) {
        output[j]   = (unsigned char)(input[i] & 0xff);
        output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

/* 将字节数组解码为 uint32_t 数组（小端序） */
void Decode(uint32_t *output, const unsigned char *input, unsigned int len) {
    unsigned int i, j;
    for(i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint32_t)input[j]) |
                    (((uint32_t)input[j+1]) << 8) |
                    (((uint32_t)input[j+2]) << 16) |
                    (((uint32_t)input[j+3]) << 24);
}

/* 初始化 MD5 上下文 */
void MD5Init(MD5_CTX *context) {
    context->count[0] = context->count[1] = 0;
    // 初始化常量
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

/* MD5Update：处理输入数据 */
void MD5Update(MD5_CTX *context, const unsigned char *input, unsigned int inputLen) {
    unsigned int index = (context->count[0] >> 3) & 0x3F;
    if((context->count[0] += inputLen << 3) < (inputLen << 3))
        context->count[1]++;
    context->count[1] += (inputLen >> 29);
    unsigned int partLen = 64 - index;
    unsigned int i = 0;
    if(inputLen >= partLen) {
        memcpy(&context->buffer[index], input, partLen);
        MD5Transform(context->state, context->buffer);
        for(i = partLen; i + 63 < inputLen; i += 64)
            MD5Transform(context->state, &input[i]);
        index = 0;
    }
    memcpy(&context->buffer[index], &input[i], inputLen - i);
}

/* MD5Final：进行填充并输出 16 字节摘要 */
void MD5Final(unsigned char digest[16], MD5_CTX *context) {
    unsigned char bits[8];
    Encode(bits, context->count, 8);
    unsigned int index = (context->count[0] >> 3) & 0x3f;
    unsigned int padLen = (index < 56) ? (56 - index) : (120 - index);
    static unsigned char PADDING[64] = { 0x80 };
    MD5Update(context, PADDING, padLen);
    MD5Update(context, bits, 8);
    Encode(digest, context->state, 16);
    memset(context, 0, sizeof(*context));
}

/* MD5Transform：对 512 位块进行 64 轮变换 */
void MD5Transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    Decode(x, block, 64);
    /* 第 1 轮 */
    FF(a, b, c, d, x[ 0], S11, 0xd76aa478);
    FF(d, a, b, c, x[ 1], S12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], S13, 0x242070db);
    FF(b, c, d, a, x[ 3], S14, 0xc1bdceee);
    FF(a, b, c, d, x[ 4], S11, 0xf57c0faf);
    FF(d, a, b, c, x[ 5], S12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], S13, 0xa8304613);
    FF(b, c, d, a, x[ 7], S14, 0xfd469501);
    FF(a, b, c, d, x[ 8], S11, 0x698098d8);
    FF(d, a, b, c, x[ 9], S12, 0x8b44f7af);
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);
    FF(b, c, d, a, x[11], S14, 0x895cd7be);
    FF(a, b, c, d, x[12], S11, 0x6b901122);
    FF(d, a, b, c, x[13], S12, 0xfd987193);
    FF(c, d, a, b, x[14], S13, 0xa679438e);
    FF(b, c, d, a, x[15], S14, 0x49b40821);
    /* 第 2 轮 */
    GG(a, b, c, d, x[ 1], S21, 0xf61e2562);
    GG(d, a, b, c, x[ 6], S22, 0xc040b340);
    GG(c, d, a, b, x[11], S23, 0x265e5a51);
    GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5], S21, 0xd62f105d);
    GG(d, a, b, c, x[10], S22, 0x2441453);
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);
    GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9], S21, 0x21e1cde6);
    GG(d, a, b, c, x[14], S22, 0xc33707d6);
    GG(c, d, a, b, x[ 3], S23, 0xf4d50d87);
    GG(b, c, d, a, x[ 8], S24, 0x455a14ed);
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);
    GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], S23, 0x676f02d9);
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);
    /* 第 3 轮 */
    HH(a, b, c, d, x[ 5], S31, 0xfffa3942);
    HH(d, a, b, c, x[ 8], S32, 0x8771f681);
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);
    HH(b, c, d, a, x[14], S34, 0xfde5380c);
    HH(a, b, c, d, x[ 1], S31, 0xa4beea44);
    HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60);
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);
    HH(d, a, b, c, x[ 0], S32, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], S33, 0xd4ef3085);
    HH(b, c, d, a, x[ 6], S34, 0x4881d05);
    HH(a, b, c, d, x[ 9], S31, 0xd9d4d039);
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
    HH(b, c, d, a, x[ 2], S34, 0xc4ac5665);
    /* 第 4 轮 */
    II(a, b, c, d, x[ 0], S41, 0xf4292244);
    II(d, a, b, c, x[ 7], S42, 0x432aff97);
    II(c, d, a, b, x[14], S43, 0xab9423a7);
    II(b, c, d, a, x[ 5], S44, 0xfc93a039);
    II(a, b, c, d, x[12], S41, 0x655b59c3);
    II(d, a, b, c, x[ 3], S42, 0x8f0ccc92);
    II(c, d, a, b, x[10], S43, 0xffeff47d);
    II(b, c, d, a, x[ 1], S44, 0x85845dd1);
    II(a, b, c, d, x[ 8], S41, 0x6fa87e4f);
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], S43, 0xa3014314);
    II(b, c, d, a, x[13], S44, 0x4e0811a1);
    II(a, b, c, d, x[ 4], S41, 0xf7537e82);
    II(d, a, b, c, x[11], S42, 0xbd3af235);
    II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb);
    II(b, c, d, a, x[ 9], S44, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof(x));
}

int main(void) {
    MD5_CTX context;
    unsigned char digest[16];
    const char *message = "The quick brown fox jumps over the lazy dog";
    MD5Init(&context);
    MD5Update(&context, (unsigned char*)message, strlen(message));
    MD5Final(digest, &context);
    printf("MD5(\"%s\") = ", message);
    for (int i = 0; i < 16; i++)
        printf("%02x", digest[i]);
    printf("\n");
    return 0;
}
```

```python
#!/usr/bin/env python3
import struct, math

def leftrotate(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def md5(message: bytes) -> str:
    # 初始化变量
    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476

    # 预处理：填充
    orig_len = len(message)
    orig_bits = orig_len * 8
    message += b'\x80'
    while (len(message) % 64) != 56:
        message += b'\x00'
    message += struct.pack("<Q", orig_bits)

    # 预计算 T[i] 常量
    T = [int((2**32) * abs(math.sin(i + 1))) & 0xffffffff for i in range(64)]

    # 定义每轮移位数（共 4 组，每组 4 个）
    shifts = [7,12,17,22, 5,9,14,20, 4,11,16,23, 6,10,15,21]

    # 分块处理，每 64 字节一块
    for offset in range(0, len(message), 64):
        chunk = message[offset:offset+64]
        M = list(struct.unpack("<16I", chunk))
        A, B, C, D = a0, b0, c0, d0

        for i in range(64):
            if 0 <= i < 16:
                f = (B & C) | ((~B) & D)
                g = i
                s = shifts[i % 4]
            elif 16 <= i < 32:
                f = (D & B) | ((~D) & C)
                g = (5 * i + 1) % 16
                s = shifts[4 + (i % 4)]
            elif 32 <= i < 48:
                f = B ^ C ^ D
                g = (3 * i + 5) % 16
                s = shifts[8 + (i % 4)]
            else:
                f = C ^ (B | (~D))
                g = (7 * i) % 16
                s = shifts[12 + (i % 4)]
            temp = (A + f + T[i] + M[g]) & 0xffffffff
            A, D, C, B = D, C, B, (B + leftrotate(temp, s)) & 0xffffffff

        a0 = (a0 + A) & 0xffffffff
        b0 = (b0 + B) & 0xffffffff
        c0 = (c0 + C) & 0xffffffff
        d0 = (d0 + D) & 0xffffffff

    # 将结果转换为 16 字节小端序
    digest = struct.pack("<4I", a0, b0, c0, d0)
    return ''.join(f'{byte:02x}' for byte in digest)

def main():
    message = b"The quick brown fox jumps over the lazy dog"
    print("MD5(\"" + message.decode() + "\") =", md5(message))

if __name__ == "__main__":
    main()
```

### SHA1

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t state[5];       // A, B, C, D, E
    uint64_t count;          // 消息总长度（以位为单位）
    unsigned char buffer[64]; // 数据缓冲区
} SHA1_CTX;

// 左循环移位 32 位整数
#define LEFTROTATE(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 初始化 SHA1 上下文
void SHA1_Init(SHA1_CTX *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

// SHA1Transform：对 512 位数据块进行 80 轮处理
void SHA1_Transform(uint32_t state[5], const unsigned char block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = LEFTROTATE(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    uint32_t a = state[0], b = state[1], c = state[2],
             d = state[3], e = state[4], f, k, temp;
    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        temp = LEFTROTATE(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = LEFTROTATE(b, 30);
        b = a;
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

// MD5Update 类似函数：处理数据并调用 Transform
void SHA1_Update(SHA1_CTX *ctx, const unsigned char *data, size_t len) {
    size_t i, index, partLen;
    index = (ctx->count / 8) % 64;
    ctx->count += (uint64_t)len * 8;
    partLen = 64 - index;
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        SHA1_Transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < len; i += 64)
            SHA1_Transform(ctx->state, &data[i]);
        index = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

// 填充消息并输出 20 字节摘要
void SHA1_Final(unsigned char digest[20], SHA1_CTX *ctx) {
    unsigned char finalcount[8];
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((ctx->count >> ((7 - i) * 8)) & 0xFF);
    }
    unsigned char pad = 0x80;
    SHA1_Update(ctx, &pad, 1);
    unsigned char zero = 0;
    while ((ctx->count / 8) % 64 != 56) {
        SHA1_Update(ctx, &zero, 1);
    }
    SHA1_Update(ctx, finalcount, 8);
    for (int i = 0; i < 5; i++) {
        digest[i*4]     = (unsigned char)((ctx->state[i] >> 24) & 0xFF);
        digest[i*4 + 1] = (unsigned char)((ctx->state[i] >> 16) & 0xFF);
        digest[i*4 + 2] = (unsigned char)((ctx->state[i] >> 8) & 0xFF);
        digest[i*4 + 3] = (unsigned char)(ctx->state[i] & 0xFF);
    }
    memset(ctx, 0, sizeof(*ctx));
}

int main(void) {
    const char *msg = "The quick brown fox jumps over the lazy dog";
    unsigned char digest[20];
    SHA1_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (const unsigned char *)msg, strlen(msg));
    SHA1_Final(digest, &ctx);
    printf("SHA1(\"%s\") = ", msg);
    for (int i = 0; i < 20; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    return 0;
}
```

```python
#!/usr/bin/env python3
import struct
import math

def leftrotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def sha1(message: bytes) -> str:
    # 初始化 5 个 32 位变量
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # 预处理：填充消息
    orig_len = len(message)
    orig_bits = orig_len * 8
    message += b'\x80'
    while (len(message) % 64) != 56:
        message += b'\x00'
    message += struct.pack('>Q', orig_bits)

    # 处理每个 512 位块
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        w = list(struct.unpack('>16I', block))
        for j in range(16, 80):
            w.append(leftrotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1))
        a, b, c, d, e = h0, h1, h2, h3, h4
        for j in range(80):
            if 0 <= j < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = (leftrotate(a, 5) + f + e + k + w[j]) & 0xffffffff
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return ''.join(f'{x:08x}' for x in (h0, h1, h2, h3, h4))

def main():
    msg = b"The quick brown fox jumps over the lazy dog"
    print("SHA1(\"" + msg.decode() + "\") =", sha1(msg))

if __name__ == "__main__":
    main()
```

### SHA256

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 64  // 512位
#define SHA256_DIGEST_SIZE 32 // 256位

// SHA-256 初始哈希值
static const uint32_t H0_INIT[8] = {
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
};

// SHA-256 常量 K[0..63]
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint32_t state[8];         // 当前哈希状态
    uint64_t bitcount;         // 消息长度（位）
    unsigned char buffer[64];  // 数据缓冲区
} SHA256_CTX;

// 右旋函数
static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 各种辅助函数
#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (rotr(x,2) ^ rotr(x,13) ^ rotr(x,22))
#define BSIG1(x) (rotr(x,6) ^ rotr(x,11) ^ rotr(x,25))
#define SSIG0(x) (rotr(x,7) ^ rotr(x,18) ^ ((x) >> 3))
#define SSIG1(x) (rotr(x,17) ^ rotr(x,19) ^ ((x) >> 10))

// 将 32 位整数数组转换为字节数组（大端）
static void Encode(unsigned char *output, const uint32_t *input, size_t len) {
    for (size_t i = 0, j = 0; j < len; i++) {
        output[j++] = (unsigned char)((input[i] >> 24) & 0xff);
        output[j++] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j++] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j++] = (unsigned char)(input[i] & 0xff);
    }
}

// 将字节数组转换为 32 位整数数组（大端）
static void Decode(uint32_t *output, const unsigned char *input, size_t len) {
    for (size_t i = 0, j = 0; j < len; i++) {
        output[i] = ((uint32_t)input[j] << 24) |
                    ((uint32_t)input[j+1] << 16) |
                    ((uint32_t)input[j+2] << 8) |
                    ((uint32_t)input[j+3]);
        j += 4;
    }
}

// SHA256Transform：处理一个 512 位数据块
void SHA256Transform(uint32_t state[8], const unsigned char block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    Decode(w, block, 64);
    for (int i = 16; i < 64; i++) {
        w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (int i = 0; i < 64; i++) {
        t1 = h + BSIG1(e) + Ch(e, f, g) + K[i] + w[i];
        t2 = BSIG0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    memset(w, 0, sizeof(w));
}

// 初始化 SHA256 上下文
void SHA256_Init(SHA256_CTX *ctx) {
    memcpy(ctx->state, H0_INIT, sizeof(H0_INIT));
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, SHA256_BLOCK_SIZE);
}

// 更新 SHA256 上下文（处理输入数据）
void SHA256_Update(SHA256_CTX *ctx, const unsigned char *data, size_t len) {
    size_t index = (ctx->bitcount / 8) % SHA256_BLOCK_SIZE;
    ctx->bitcount += (uint64_t)len * 8;
    size_t partLen = SHA256_BLOCK_SIZE - index;
    size_t i = 0;
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        SHA256Transform(ctx->state, ctx->buffer);
        for (i = partLen; i + SHA256_BLOCK_SIZE - 1 < len; i += SHA256_BLOCK_SIZE)
            SHA256Transform(ctx->state, &data[i]);
        index = 0;
    }
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

// 最终填充并输出 32 字节摘要
void SHA256_Final(unsigned char digest[SHA256_DIGEST_SIZE], SHA256_CTX *ctx) {
    unsigned char bits[8];
    uint32_t index = (ctx->bitcount / 8) % SHA256_BLOCK_SIZE;
    // 以大端存储长度（64位）
    for (int i = 0; i < 8; i++) {
        bits[i] = (unsigned char)((ctx->bitcount >> (56 - 8*i)) & 0xff);
    }
    // 填充: 先加 0x80，再补零直到长度 ≡ 56 mod 64
    unsigned char pad = 0x80;
    SHA256_Update(ctx, &pad, 1);
    unsigned char zero = 0x00;
    while ((ctx->bitcount / 8) % SHA256_BLOCK_SIZE != 56) {
        SHA256_Update(ctx, &zero, 1);
    }
    SHA256_Update(ctx, bits, 8);
    // 输出哈希（大端）
    Encode(digest, ctx->state, SHA256_DIGEST_SIZE);
    memset(ctx, 0, sizeof(*ctx));
}

int main(void) {
    const char *msg = "The quick brown fox jumps over the lazy dog";
    unsigned char digest[SHA256_DIGEST_SIZE];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)msg, strlen(msg));
    SHA256_Final(digest, &ctx);
    printf("SHA256(\"%s\") = ", msg);
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    return 0;
}
```

```python
#!/usr/bin/env python3
import struct

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def sha256(message: bytes) -> str:
    # 初始状态
    H = [
        0x6a09e667, 0xbb67ae85,
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    ]
    K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]
    # 填充
    orig_len = len(message)
    message += b'\x80'
    while (len(message) % 64) != 56:
        message += b'\x00'
    message += struct.pack(">Q", orig_len * 8)
    # 分块处理
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = list(struct.unpack(">16I", chunk))
        for j in range(16, 64):
            s0 = rotr(w[j-15], 7) ^ rotr(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = rotr(w[j-2], 17) ^ rotr(w[j-2], 19) ^ (w[j-2] >> 10)
            w.append((w[j-16] + s0 + w[j-7] + s1) & 0xffffffff)
        a, b, c, d, e, f, g, h = H
        for j in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + K[j] + w[j]) & 0xffffffff
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff
        H[0] = (H[0] + a) & 0xffffffff
        H[1] = (H[1] + b) & 0xffffffff
        H[2] = (H[2] + c) & 0xffffffff
        H[3] = (H[3] + d) & 0xffffffff
        H[4] = (H[4] + e) & 0xffffffff
        H[5] = (H[5] + f) & 0xffffffff
        H[6] = (H[6] + g) & 0xffffffff
        H[7] = (H[7] + h) & 0xffffffff
    return ''.join(f'{x:08x}' for x in H)

def main():
    msg = b"The quick brown fox jumps over the lazy dog"
    print("SHA256(\"" + msg.decode() + "\") =", sha256(msg))

if __name__ == "__main__":
    main()
```

### CRC32

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CRC32_POLY 0xEDB88320UL

// 全局 CRC32 查找表，共 256 个 32 位数
static uint32_t crc32_table[256];

// 初始化 CRC32 查找表
void init_crc32_table(void) {
    uint32_t c;
    for (uint32_t n = 0; n < 256; n++) {
        c = n;
        for (int k = 0; k < 8; k++) {
            if (c & 1)
                c = CRC32_POLY ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc32_table[n] = c;
    }
}

// 计算 CRC32 值，对输入 buf 的 len 字节进行处理
uint32_t crc32(const unsigned char *buf, size_t len) {
    uint32_t c = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        c = crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

int main(void) {
    init_crc32_table();
    const char *str = "The quick brown fox jumps over the lazy dog";
    uint32_t crc = crc32((const unsigned char *)str, strlen(str));
    printf("CRC32(\"%s\") = %08X\n", str, crc);
    return 0;
}
```

```python
#!/usr/bin/env python3

def init_crc32_table():
    poly = 0xEDB88320
    table = []
    for n in range(256):
        c = n
        for k in range(8):
            if c & 1:
                c = poly ^ (c >> 1)
            else:
                c = c >> 1
        table.append(c)
    return table

def crc32(data: bytes) -> int:
    table = init_crc32_table()
    c = 0xFFFFFFFF
    for byte in data:
        c = table[(c ^ byte) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF

def main():
    s = b"The quick brown fox jumps over the lazy dog"
    print("CRC32:", format(crc32(s), '08X'))

if __name__ == "__main__":
    main()
```



### SM3

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SM3_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];         // 8 个 32 位状态
    uint64_t bitcount;         // 已处理的消息位数
    unsigned char buffer[64];  // 数据缓冲区
} SM3_CTX;

// 左循环移位
static inline uint32_t leftrotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// P0 与 P1 变换
static inline uint32_t P0(uint32_t x) {
    return x ^ leftrotate(x, 9) ^ leftrotate(x, 17);
}
static inline uint32_t P1(uint32_t x) {
    return x ^ leftrotate(x, 15) ^ leftrotate(x, 23);
}

// SM3 初始化：设置初始 IV 值
void SM3_Init(SM3_CTX *ctx) {
    ctx->bitcount = 0;
    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
}

// SM3_Compress：处理一个 512 位消息块
void SM3_Compress(SM3_CTX *ctx, const unsigned char block[64]) {
    uint32_t W[68], W1[64];
    // 将 block 按大端方式分成 16 个 32 位字
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i*4] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    // 消息扩展
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i-16] ^ W[i-9] ^ leftrotate(W[i-3], 15)) ^ leftrotate(W[i-13], 7) ^ W[i-6];
    }
    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i+4];
    }
    // 初始化工作变量
    uint32_t A = ctx->state[0];
    uint32_t B = ctx->state[1];
    uint32_t C = ctx->state[2];
    uint32_t D = ctx->state[3];
    uint32_t E = ctx->state[4];
    uint32_t F = ctx->state[5];
    uint32_t G = ctx->state[6];
    uint32_t H = ctx->state[7];
    uint32_t SS1, SS2, TT1, TT2;
    for (int j = 0; j < 64; j++) {
        uint32_t T = (j < 16) ? 0x79CC4519 : 0x7A879D8A;
        SS1 = leftrotate((leftrotate(A, 12) + E + leftrotate(T, j)) & 0xFFFFFFFF, 7);
        SS2 = SS1 ^ leftrotate(A, 12);
        if (j < 16) {
            TT1 = (A ^ B ^ C) + D + SS2 + W1[j];
            TT2 = (E ^ F ^ G) + H + SS1 + W[j];
        } else {
            TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j];
            TT2 = ((E & F) | ((~E) & G)) + H + SS1 + W[j];
        }
        TT1 &= 0xFFFFFFFF;
        TT2 &= 0xFFFFFFFF;
        D = C;
        C = leftrotate(B, 9);
        B = A;
        A = TT1 & 0xFFFFFFFF;
        H = G;
        G = leftrotate(F, 19);
        F = E;
        E = P0(TT2);
    }
    // 更新状态：按位异或累加
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

// SM3_Update：更新数据
void SM3_Update(SM3_CTX *ctx, const unsigned char *data, size_t len) {
    size_t index = (ctx->bitcount / 8) % SM3_BLOCK_SIZE;
    ctx->bitcount += (uint64_t)len * 8;
    size_t partLen = SM3_BLOCK_SIZE - index;
    size_t i = 0;
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        SM3_Compress(ctx, ctx->buffer);
        for (i = partLen; i + SM3_BLOCK_SIZE - 1 < len; i += SM3_BLOCK_SIZE)
            SM3_Compress(ctx, &data[i]);
        index = 0;
    }
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

// SM3_Final：进行填充并输出 32 字节摘要（以大端序输出）
void SM3_Final(unsigned char digest[32], SM3_CTX *ctx) {
    unsigned char pad[SM3_BLOCK_SIZE] = {0x80};
    unsigned char len_bytes[8];
    // 将 bitcount 以 64 位大端格式保存
    for (int i = 0; i < 8; i++) {
        len_bytes[i] = (unsigned char)((ctx->bitcount >> (56 - i*8)) & 0xFF);
    }
    size_t index = (ctx->bitcount / 8) % SM3_BLOCK_SIZE;
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);
    SM3_Update(ctx, pad, padLen);
    SM3_Update(ctx, len_bytes, 8);
    // 输出结果（大端序，每个 state 单元输出 4 字节）
    for (int i = 0; i < 8; i++) {
        digest[i*4]     = (unsigned char)((ctx->state[i] >> 24) & 0xFF);
        digest[i*4 + 1] = (unsigned char)((ctx->state[i] >> 16) & 0xFF);
        digest[i*4 + 2] = (unsigned char)((ctx->state[i] >> 8) & 0xFF);
        digest[i*4 + 3] = (unsigned char)(ctx->state[i] & 0xFF);
    }
    // 清理
    memset(ctx, 0, sizeof(*ctx));
}

int main(void) {
    const char *message = "The quick brown fox jumps over the lazy dog";
    unsigned char digest[32];
    SM3_CTX ctx;
    SM3_Init(&ctx);
    SM3_Update(&ctx, (const unsigned char *)message, strlen(message));
    SM3_Final(digest, &ctx);
    printf("SM3(\"%s\") = ", message);
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    return 0;
}
```

```python
#!/usr/bin/env python3
import struct

def leftrotate(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def P0(x):
    return x ^ leftrotate(x, 9) ^ leftrotate(x, 17)

def P1(x):
    return x ^ leftrotate(x, 15) ^ leftrotate(x, 23)

# SM3 初始向量
IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

def sm3_compress(V, block):
    # 将 64 字节块解析为 16 个 32 位大端整数
    W = list(struct.unpack(">16I", block))
    # 消息扩展
    for j in range(16, 68):
        W.append(P1(W[j-16] ^ W[j-9] ^ leftrotate(W[j-3], 15)) ^ leftrotate(W[j-13], 7) ^ W[j-6])
    W1 = [W[j] ^ W[j+4] for j in range(64)]
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        T = 0x79CC4519 if j < 16 else 0x7A879D8A
        SS1 = leftrotate((leftrotate(A,12) + E + leftrotate(T, j)) & 0xffffffff, 7)
        SS2 = SS1 ^ leftrotate(A,12)
        if j < 16:
            FF = A ^ B ^ C
            GG = E ^ F ^ G
        else:
            FF = (A & B) | (A & C) | (B & C)
            GG = (E & F) | ((~E) & G)
        TT1 = (FF + D + SS2 + W1[j]) & 0xffffffff
        TT2 = (GG + H + SS1 + W[j]) & 0xffffffff
        D = C
        C = leftrotate(B, 9)
        B = A
        A = TT1
        H = G
        G = leftrotate(F, 19)
        F = E
        E = P0(TT2)
    # 迭代更新：新 V = 原 V XOR (A,B,C,...,H)
    return [V[i] ^ x for i, x in enumerate([A, B, C, D, E, F, G, H])]

def sm3(message: bytes) -> str:
    # 预处理：填充
    mlen = len(message)
    bit_len = mlen * 8
    message += b'\x80'
    while (len(message) % 64) != 56:
        message += b'\x00'
    message += struct.pack(">Q", bit_len)
    # 初始状态
    V = IV.copy()
    # 逐块压缩
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        V = sm3_compress(V, block)
    # 输出 32 字节大端序哈希
    return ''.join(f'{x:08x}' for x in V)

def main():
    msg = b"The quick brown fox jumps over the lazy dog"
    print(f"SM3(\"{msg.decode()}\") = {sm3(msg)}")

if __name__ == "__main__":
    main()
```

