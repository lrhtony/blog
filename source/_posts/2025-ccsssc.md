---
title: 2025 CCSSSC Reverse Writeup
comments: true
date: 2025-01-08 14:32:38
tags:
  - CTF
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzfrrsarktcrufd2lf2ccsis5vsz
---

封面：Bison仓鼠

第二天早九考试，看了看题没怎么打，考完期末考来补，搜了一下已经有全部wp了，随便写下分析过程吧

## donntyousee

第一眼看到题目发现静态编译删除了所有符号，搜索字符串关键词找不到相关函数，得知字符串有加密就跑了。后面再看题目还挺简单。

原本是想着恢复符号再做，但是编译的gcc版本较新，搜了下应该是Ubuntu24的，找不到sig，又懒得自己做，就没恢复。实际上没恢复符号对这题影响并不是很大。

首先就是要找到输出plz input your flag的

经过调试可以发现，程序在`sub_4B5470`中利用循环按顺序调用了`.init_array`的函数，其中第三个函数`sub_4053A5`输出了该字符串。追踪进去可以发现存在花指令，这里通过调试和观察汇编，可以把`push rax`和`pop rax`之间的花指令nop掉

![image-20250108161402920](https://img.0a0.moe/od/01tklsjzffjplpfnfwardz2tqpwlw3mxi2)

同理把上下周围几个有类似花指令的的函数patch掉，方便后面分析

然后反编译即可看到该函数逐字节`XOR 0x23`输出。同时在这里有一个对`byte_5C5110`的异或，当时并没怎么在意。

然后通过调试发现在`sub_405559`中，通过调用`sub_405848`传入`byte_5C5110`初始化了个S盒，然后调用`sub_405EAA`使用魔改RC4将输入加密

查找这两个函数的引用，可以找到`.data.rel.ro`段，在这个列表中下面的函数`sub_405CAA`即可发现是检验函数，字符串同样做了异或处理。于是我打算将此处的加密数据通过patch输入回程序中，观察异或回去的输出，却发现是乱码。

此处我首先怀疑是异或完后是否有对数据作进一步处理，但经过交叉引用和动调后确认没有对数据进行修改。然后这时候就怀疑是上面对`byte_5C5110`的异或。查看异或判断是否执行的函数`sub_529980`，有个非常明显的`sys_ptrace`反调试。因此只需要对此处反调试作处理即可，方法多样

```python
# S = [0x34, 0x55, 0xA1, 0xFE, 0x31, 0x78, 0xB1, 0x72, 0x9B, 0xA0, 0xB7, 0x75, 0x42, 0xAF, 0xE4, 0x5F, 0x2E, 0x09, 0xAC, 0xA4, 0x9A, 0x15, 0xE9, 0x4D, 0x7C, 0x13, 0x12, 0x22, 0x91, 0x8B, 0xC0, 0x19, 0x5E, 0x8E, 0x1F, 0x6D, 0x25, 0x1D, 0x68, 0x64, 0x3A, 0x4A, 0x50, 0x2D, 0x26, 0xE3, 0xA7, 0xB9, 0x7B, 0xCF, 0x43, 0x2B, 0xBB, 0x4C, 0x54, 0x62, 0x21, 0x02, 0x60, 0x0A, 0xF8, 0xF7, 0xF4, 0xED, 0x7E, 0xDC, 0x4B, 0x38, 0x44, 0x69, 0x86, 0x82, 0x41, 0x7F, 0xD6, 0x03, 0x65, 0x1A, 0x84, 0xA8, 0xB4, 0x33, 0x0F, 0x46, 0xAE, 0x63, 0xE8, 0x10, 0x30, 0xE1, 0x6C, 0x6A, 0x04, 0x18, 0x0D, 0x06, 0xA6, 0xCA, 0xAA, 0x17, 0x81, 0xE6, 0xD1, 0xAB, 0x24, 0xBE, 0x5B, 0x27, 0xFB, 0xC6, 0x05, 0xCD, 0x70, 0xD5, 0xC8, 0x1E, 0x96, 0x71, 0x3E, 0x66, 0x98, 0xBD, 0x2A, 0xC2, 0xA5, 0xAD, 0x6F, 0xE2, 0x89, 0xDB, 0x14, 0x97, 0xB0, 0xCB, 0x83, 0x01, 0x8F, 0xE7, 0xB8, 0x9E, 0xC3, 0xA9, 0x92, 0x76, 0x56, 0x1C, 0x45, 0x93, 0x59, 0xB2, 0x32, 0x3B, 0x16, 0x4E, 0x58, 0xBC, 0xF6, 0xF1, 0xD3, 0x39, 0x85, 0xC5, 0x40, 0x36, 0xDD, 0x8A, 0x61, 0xD0, 0xB6, 0x07, 0xD4, 0x0B, 0x9C, 0x6E, 0xF0, 0xEE, 0x95, 0x3C, 0x5A, 0xDE, 0xEF, 0xF9, 0xFA, 0x51, 0x0C, 0x37, 0xEA, 0x35, 0x48, 0x67, 0xD2, 0x47, 0x2C, 0xE5, 0x9F, 0xA3, 0xB3, 0x80, 0xF5, 0xE0, 0x52, 0x8C, 0xDF, 0x9D, 0x28, 0x8D, 0xFF, 0x53, 0x7A, 0x29, 0x7D, 0x08, 0xDA, 0x57, 0xA2, 0x79, 0xF2, 0xCC, 0x2F, 0x6B, 0xBF, 0x49, 0xEB, 0xFD, 0x90, 0x00, 0xC7, 0x3D, 0x94, 0xD7, 0x3F, 0x5C, 0xD8, 0xC4, 0x5D, 0x20, 0xC9, 0x11, 0xBA, 0x87, 0x74, 0xC1, 0xD9, 0x0E, 0x4F, 0xB5, 0x88, 0xF3, 0xFC, 0xEC, 0xCE, 0x23, 0x1B, 0x99, 0x77, 0x73]  wrong!
S = [0x92, 0xFF, 0xDC, 0x68, 0x55, 0x4D, 0x30, 0x11, 0xF6, 0xC6, 0x1C, 0xF5, 0x18, 0x58, 0xD8, 0x7C, 0xB7, 0xE7, 0x4F, 0xC1, 0x77, 0x8B, 0xA8, 0x0B, 0xC5, 0xAA, 0x3B, 0x98, 0xC8, 0x25, 0x4A, 0x88, 0x13, 0x33, 0xA0, 0x9B, 0x8F, 0xAF, 0xC0, 0x1F, 0xEE, 0x8A, 0x19, 0x86, 0x5F, 0xE8, 0xA6, 0xFA, 0xCC, 0xFC, 0x71, 0x40, 0x0C, 0x7B, 0x9D, 0xAC, 0x64, 0x5B, 0x78, 0x20, 0xF4, 0xEA, 0x06, 0x61, 0x99, 0x03, 0x2E, 0x7A, 0xE0, 0xDB, 0x56, 0xD2, 0xBB, 0x3D, 0x85, 0x53, 0x07, 0x04, 0x5A, 0x3A, 0xDF, 0x4E, 0xB0, 0x49, 0x60, 0xBC, 0x27, 0xE6, 0xB1, 0x3F, 0x23, 0x89, 0x0F, 0x65, 0x80, 0xC9, 0x50, 0xF2, 0x29, 0xB4, 0xF3, 0x7D, 0x2B, 0xF9, 0xFE, 0x6B, 0x76, 0xA2, 0x9A, 0x0D, 0x9E, 0x31, 0xC3, 0x74, 0x72, 0x84, 0xD5, 0x4C, 0x67, 0xA3, 0x02, 0xB9, 0x2C, 0x95, 0xEC, 0xA9, 0x6D, 0x12, 0x1E, 0x2A, 0x5C, 0x36, 0xDE, 0x15, 0x32, 0x59, 0x10, 0x73, 0x22, 0xB6, 0x2D, 0x87, 0xDD, 0xE4, 0x39, 0x9F, 0xA1, 0xE2, 0xD7, 0x45, 0xD4, 0x7F, 0x54, 0x16, 0x8C, 0x01, 0x1A, 0x08, 0x6F, 0x44, 0x42, 0x5D, 0x8E, 0xB2, 0xB5, 0x97, 0xD0, 0x90, 0x91, 0xF8, 0xCD, 0xBD, 0x57, 0x69, 0x3E, 0xAE, 0xCE, 0xC7, 0xC2, 0xF0, 0xBA, 0xE3, 0x34, 0x5E, 0x0A, 0xE1, 0x28, 0x46, 0xEF, 0x09, 0xA5, 0x17, 0xB3, 0xD9, 0xD6, 0x75, 0x3C, 0x21, 0xEB, 0x6C, 0xB8, 0x47, 0x6E, 0xCF, 0x38, 0x41, 0x9C, 0x7E, 0x1B, 0x4B, 0x2F, 0xE9, 0x66, 0x35, 0xD3, 0x14, 0x51, 0x62, 0x1D, 0x48, 0x26, 0x96, 0xAD, 0xA4, 0xED, 0xBE, 0x05, 0x81, 0x00, 0x70, 0xF7, 0x6A, 0x82, 0x63, 0x43, 0xCB, 0xCA, 0xD1, 0x8D, 0xBF, 0xAB, 0x93, 0xA7, 0x83, 0x24, 0x37, 0x79, 0xFB, 0x94, 0x0E, 0x52, 0xFD, 0xE5, 0xC4, 0xF1, 0xDA]

def decrypt(k):
    v5 = 0
    v6 = 0
    for i in range(len(k)):
        v5 = (v5 + 1) % 256
        v6 = (v6 + S[v5]) % 256
        v4 = S[v5]
        S[v5] = S[v6]
        S[v6] = v4
        k[i] = k[i] ^ S[(S[v5] + S[v6]) % 256] ^ 0x23
    return k

if __name__ == '__main__':
    k = [0x25, 0xCD, 0x54, 0xAF, 0x51, 0x1C, 0x58, 0xD3, 0xA8, 0x4B, 0x4F, 0x56, 0xEC, 0x83, 0x5D, 0xD4, 0xF6, 0x47, 0x4A, 0x6F, 0xE0, 0x73, 0xB0, 0xA5, 0xA8, 0xC3, 0x17, 0x81, 0x5E, 0x2B, 0xF4, 0xF6, 0x71, 0xEA, 0x2F, 0xFF, 0xA8, 0x63, 0x99, 0x57]
    print(bytes(decrypt(k)).decode())
# dart{y0UD0ntL4cKg0oD3y34T0F1nDTh3B4aUtY}
```

## kernel_traffic

三个文件：内核、client、流量。反编译一下可发现，内核将key事件发送给client，client通过一定的加密后发送给server，而流量文件的内容是client和server间的通信。这里缺少server文件，只能通过client的操作猜测

可以看到在main函数里首先进入一个函数，里面有两个大数。根据动调结果以及函数的传参分析，大概可以整理得到

![image-20250109154711014](https://img.0a0.moe/od/01tklsjzctjkccwowjzrekfll36soujg3z)

对于上面的大数以及65537，猜测是rsa加密，可以验证一下

![image-20250109154737013](https://img.0a0.moe/od/01tklsjzd5o6otwsjuc5d26aolo3imisfu)

确实是公钥和私钥。因此我们可以通过流量得到通讯时使用的密钥。这题要注意数字的大小端序的问题

得到两端的密钥通过相乘异或计算后在下面初始化了一个魔改的RC4 S盒

看回主函数，下面有一个循环，获取内核发来的数据，然后使用生成的S盒进行魔改RC4加密，然后通过timestamp打乱一个table，对加密后的数据再进行一个替换

```python
import ctypes

n = 0x00b7db0b385f4cfb85bf9af7c1c8298ec4d691c8341b8a09d3e0f1685f1e9e8198b03426855ee144c38c10b623ae2f1f671b9aee7a8a7a49fc46154c5d57d1827c28bdf1aeb7cbf259ee1564dd24fcaa66f1e95db6652bbd8f4b1ef1a7bd698085609b8d50a714162bedc8f9478807984fa257ba6647d0a18cb5595bcd789cb8b7
d = 0x18260d333a5142382f128bb848322d2e6d80786b5fb2a1d7d293e2c19ba3f621b803218c230a339dfba7b644b97c3703b3fc859652d9fd1dc596c690fc17e8ab6d2de44fcddc6d7af84fc50175347cebf1aeb4c920036fab4a20b4ba44b72f69d45e6ed40111bff5d1186087dc40d31c22bec7bdd6c39e079c518a2a385ecb01
e = 65537

k1_enc = 0x44cde3547452c9a91ba250747568bf5fa64cc42fa99111d33a51e82aa99e20a2f07073cc1ba492243964fd85834526ebc6bc6ed0e4216353efb8b9561d94bf0c5a3bbb8c452bdc961c9136f90860e76239cc22ddf9293bc3e23f0c7b3873d58cdde51edf1d8864e47708dd811b29dede65971f9fad6fa8c38aca2b4e98736267
k2_enc = 0x81281a405e55002bb71c31b7429d0240fdc14fa4a5e646ed6bf888cd5d1ae6a8fda3added2cbb29a3be7f41359e1ff40e6763bfb843a8e417f799062dbe3207ccaf56d09a7c70cd45d48032f35ca8b485d4c372d42164c6a90e15824ea95cd426dab6de5d065d19fe31b2e72662393f422af8c0b20d478c23baf63ccec0a18ac

k1 = pow(k1_enc, d, n).to_bytes(16, 'little')
k2 = pow(k2_enc, d, n).to_bytes(16, 'little')

key = []
for i in range(16):
    key.append((k1[i] ^ (17*k2[i]))&0xff)

S = [0 for i in range(256)]
v7 = [0 for i in range(256)]
for i in range(256):
    S[i] = i
    v7[i] = key[i % 16]
v6 = 0
for j in range(256):
    v6 = (v7[j] + v6 + S[j]) % 256
    S[j], S[v6] = S[v6], S[j]

encrypt_data = [["c9a43567", "a92066b352dd8b65a0840fba"], ["c9a43567", "d21c608abafe1fa3ed22ee1b"], ["caa43567", "5cd8e734e9ff3ddc88f82ff6"], ["cba43567", "0f2c1f33a63872e89d85419d"], ["cda43567", "9c4c416a6c33912c5d2dbea3"], ["cda43567", "3405e1f86f204cb3233cee47"], ["cfa43567", "babf35d58fb039f34ac0bc68"], ["d0a43567", "69c3563248492fa3dd39c300"], ["d1a43567", "9660928ac69bd2c5ed38c575"], ["d3a43567", "8068f321bb9f3ad2db1733fc"], ["d4a43567", "d0d76861912565a75fab99ea"], ["d4a43567", "d5e4f21427976a29b28d2465"], ["d5a43567", "b8dc14e8f9e098ee0eae689c"], ["d5a43567", "8d0a397c810b8e6387dc5317"], ["d5a43567", "1a972a6c158c1bda02fc43de"], ["d5a43567", "297eaa03818999b004297ca8"], ["d5a43567", "c66c97a36a413d0fe38a57c5"], ["d8a43567", "1809619ecdf37f837d44f986"], ["d8a43567", "3b52e6a439e9f1ee97daa235"], ["d9a43567", "a44507aa2e755b35675722fc"], ["dba43567", "12d4da0167e78a3cd8080e4e"], ["dda43567", "83202fb19c2937cb9e3015e1"], ["dda43567", "a34e094fd2e4cc0fc0d52e08"], ["e0a43567", "c5323082d0db41cc22eaf37e"], ["e0a43567", "c2fe09cd87dd6b8dc540b11f"], ["e1a43567", "9f34dc29085976f1f1f4804c"], ["e1a43567", "5928e0ea62033a917bbe2439"], ["e1a43567", "25e8f3be3759dae1dddf5760"], ["e1a43567", "a1985a4755ed3b39af887410"], ["e1a43567", "b6dd7db5d3da879d6fcce465"], ["e1a43567", "907194e5ccf0ab56d9cee5fc"], ["e1a43567", "a0d42f568286477b5000a21e"], ["e3a43567", "fab0826bcd5e77a70d11ca95"], ["e3a43567", "3c0b8f780746b6c870b8eb3d"], ["e6a43567", "a25ad5f8ab74414f116791af"], ["e8a43567", "31b2eed379afb67f9aa962bf"], ["e8a43567", "802421958e372da29ca75ae7"], ["eba43567", "ed3db7f76f2b1fc8ace9dccb"], ["eba43567", "12b5a5a2a5a161c619319de9"], ["eba43567", "aefd55c6cdbef465b24dca78"], ["eba43567", "daf9a0aef390e56d2c59da48"], ["f0a43567", "a7e1347f096846f5b8f08c8b"], ["f1a43567", "4754a89602a3902d44f2d151"], ["f1a43567", "92a034c0c522c297349f7cff"], ["f3a43567", "19a5598acb6abf72ab62e79c"], ["f4a43567", "ebcca8b0c020566761d8484b"], ["f5a43567", "bc65b1fd58a6c24a2bcdb23c"], ["f5a43567", "dee8f9c766cb33cb771f8bab"], ["f6a43567", "547c2274e7be1e8a492d2566"], ["f6a43567", "5c60476d6f22c523af08e883"], ["f6a43567", "29ea7e1ccd945a6fec3f1bbf"], ["f6a43567", "816f99fc399b312a76a61b97"]]

noShift = {0: '[Null]', 1: '[ESC]', 2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0', 12: '-', 13: '=', 14: '[Backspace]', 15: '[Tab]', 16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p', 26: '[', 27: ']', 28: '[Enter]', 29: '[Left Ctrl]', 30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';', 40: "'", 41: '`', 42: '[Left Shift]', 43: '\\', 44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm', 51: ',', 52: '.', 53: '/', 54: '[Right Shift]', 55: '*', 56: '[Left Alt]', 57: '[Space]', 58: '[Caps Lock]', 59: '[F1]', 60: '[F2]', 61: '[F3]', 62: '[F4]', 63: '[F5]', 64: '[F6]', 65: '[F7]', 66: '[F8]', 67: '[F9]', 68: '[F10]', 87: '[F11]', 88: '[F12]', 224: '[Right Ctrl]', 225: '[Print Screen]', 226: '[Scroll Lock]', 227: '[Pause]', 228: '[Insert]', 229: '[Home]', 230: '[Page Up]', 231: '[Delete]', 232: '[End]', 233: '[Page Down]', 234: '[Up Arrow]', 235: '[Left Arrow]', 236: '[Down Arrow]', 237: '[Right Arrow]'}
leftShift = {0: '[Null]', 1: '[ESC]', 2: '!', 3: '@', 4: '#', 5: '$', 6: '%', 7: '^', 8: '&', 9: '*', 10: '(', 11: ')', 12: '_', 13: '+', 14: '[Backspace]', 15: '[Tab]', 16: 'Q', 17: 'W', 18: 'E', 19: 'R', 20: 'T', 21: 'Y', 22: 'U', 23: 'I', 24: 'O', 25: 'P', 26: '{', 27: '}', 28: '[Enter]', 29: '[Left Ctrl]', 30: 'A', 31: 'S', 32: 'D', 33: 'F', 34: 'G', 35: 'H', 36: 'J', 37: 'K', 38: 'L', 39: ':', 40: '"', 41: '~', 42: '[Left Shift]', 43: '|', 44: 'Z', 45: 'X', 46: 'C', 47: 'V', 48: 'B', 49: 'N', 50: 'M', 51: '<', 52: '>', 53: '?', 54: '[Right Shift]', 55: '*', 56: '[Left Alt]', 57: '[Space]', 58: '[Caps Lock]', 59: '[F1]', 60: '[F2]', 61: '[F3]', 62: '[F4]', 63: '[F5]', 64: '[F6]', 65: '[F7]', 66: '[F8]', 67: '[F9]', 68: '[F10]', 87: '[F11]', 88: '[F12]', 224: '[Right Ctrl]', 225: '[Print Screen]', 226: '[Scroll Lock]', 227: '[Pause]', 228: '[Insert]', 229: '[Home]', 230: '[Page Up]', 231: '[Delete]', 232: '[End]', 233: '[Page Down]', 234: '[Up Arrow]', 235: '[Left Arrow]', 236: '[Down Arrow]', 237: '[Right Arrow]'}

C = ctypes.CDLL('libc.so.6')
a = b = 0
flag = ''
for data in encrypt_data:
    timestamp = int.from_bytes(bytes.fromhex(data[0]), 'little')
    table = [i for i in range(256)]
    C.srand(timestamp)
    for j in range(255, 0, -1):
        k = C.rand() % (j + 1)
        table[j], table[k] = table[k], table[j]
    data = bytes.fromhex(data[1])
    data = [table.index(i) for i in data]
    for i in range(12):
        a = (a + 1) % 256
        b = (b + S[a]) % 256
        S[a], S[b] = S[b], S[a]
        data[i] ^= S[(S[a] + S[b]) % 256]
    print(''.join([hex(i)[2:].zfill(2) for i in data]))
    if data[0]:
        flag += leftShift[data[8]]
    else:
        flag += noShift[data[8]]
print(flag.replace('[Left Shift]', ''))
# flag{k3rnel_Tr4ffic_G4me_H4ha}
```

参考：

https://www.52pojie.cn/thread-1997919-1-1.html

https://blog.csdn.net/weixin_45582916/article/details/144962552

## happyLock

A15的frida炸了，暂时咕咕，快发版修复了等一下

## 生日邮件

打开邮件，发现压缩包，提取，发现存在密码，根据邮件内容猜测密码为生日20001111。密码正确，得到生日快乐.exe，丢云沙箱分析。VirusTotal和微步都没分析出来，多试几个总有可以的。查看分析报告得到外联ip和端口。
