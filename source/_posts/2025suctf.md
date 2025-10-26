---
title: 2025 SUCTF 逆向部分Writeup
comments: true
date: 2025-01-14 20:55:40
tags:
  - CTF
  - 逆向
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzf3lnpqlkzecncyno5thmxd5hqx
---

> 封面：[X-6](https://www.pixiv.net/users/2932264) 国人画师，但好像没找到Weibo？

最近几天街角魔族还有舞台剧来着，有空看看（）

就写一下我看过的题

## SU_BBRE
经验+AI。把RC4和那个那个减去序数的解出来就行。然后根据这两部分提示PWN，看了一下输入的和前面的scanf("%19s")长度对不上，又看到function0里面有个strcpy，发现栈溢出，利用ret2text，输入加上function1地址0x0040223D即`="@`即可。拼接起来即是

```
We1com3ToReWorld="@AndPWNT00
```

## SU_mapmap2

经典的迷宫题，搜索wrong即可找到主函数。先是创建一个map，这个map在堆里。然后获取输入，判断输入长度是否为268，然后循环取出每个字符，判断是否为asdw的其中一个，然后分别传到两个函数里面去走迷宫。

我在做这题的时候没能分析出这两个函数是怎么走的，但是我们可以发现每一个字符走完后会把当前地址存储在栈中。通常迷宫题要的都是最短路径，我们可以通过每个字符每个字符输入，判断当前地址是否与之前的重复，重复了就不是最短路径就要舍弃尝试另一个。

根据这个原理我们通过在运行时hook相应的栈来解决题目。刚开始是打算用Frida的，但是报错找不到libc基址，因为这题是静态编译的。找了一下issue发现好像不支持https://github.com/frida/frida/issues/1143。于是找模拟执行去做，找到了[Qiling](https://github.com/qilingframework/qiling)

第一次用就搜文档，按照报错把elf文件放到rootfs里面，然后根据报错设置`multithread=True`，run程序就跑起来了，输入输出都没问题。按照教程hook每次循环进入的地址，调用接口读出stack里面的位置，好像是相对rsp的偏移，发现跟直接运行程序的结果一样，就直接写脚本了。这里我禁用了其他输出来加快速度

```python
from qiling import *
from qiling.extensions import pipe
from qiling.const import QL_VERBOSE

addr_list = []
start_addr = 0
end_addr = 0

def get_start_and_end(ql: Qiling):
    global start_addr, end_addr
    start_addr = int.from_bytes(ql.mem.read(0x063F530, 8), 'little')
    end_addr = int.from_bytes(ql.mem.read(0x63F538, 8), 'little')
    print('[+] start:',hex(start_addr))
    print('[+] end:  ',hex(end_addr))

def hook(ql: Qiling):
    now_addr = ql.stack_read(0x10)
    global addr_list
    addr_list.append(now_addr)
    # print(hex(now_addr))

def find(flag, length):
    if length >= 268:
        # print(flag)
        return
    # a
    flag_tmp = flag + 'a'
    if run(flag_tmp.ljust(268, 'o'), length+1):
        find(flag_tmp, length + 1)
    # s
    flag_tmp = flag + 's'
    if run(flag_tmp.ljust(268, 'o'), length+1):
        find(flag_tmp, length + 1)
    # d
    flag_tmp = flag + 'd'
    if run(flag_tmp.ljust(268, 'o'), length+1):
        find(flag_tmp, length + 1)
    # w
    flag_tmp = flag + 'w'
    if run(flag_tmp.ljust(268, 'o'), length+1):
        find(flag_tmp, length + 1)

def run(input_str:str, length:int):
    global addr_list
    addr_list = []
    path = ['./qiling-rootfs/x8664_linux/mapmap2']
    rootfs = "./qiling-rootfs/x8664_linux"
    ql = Qiling(path, rootfs, multithread=True, verbose=QL_VERBOSE.DISABLED)
    ql.os.stdin = pipe.SimpleInStream(0)
    ql.os.stdin.write((input_str+'\n').encode())
    ql.os.stdout = pipe.SimpleOutStream(0)
    # ql.hook_address(get_start_and_end, 0x462DD0)
    ql.hook_address(hook, 0x462eaa)
    ql.run()
    check_path = addr_list[:length+1]
    # 判断里面是否有重复的地址或0
    # print(input_str)
    # print(check_path)
    print('[*] length:', length)
    if len(check_path) != len(set(check_path)) or 0 in check_path:
        return False
    if length >= 268:
        output = ql.os.stdout.read().decode()
        if 'SUCTF' in output:
            print('[+] find flag:', input_str)
            exit(0)
    return True

if __name__ == '__main__':
    find('', 0)
```

![image-20250115171633388](https://img.0a0.moe/od/01tklsjzavrt5it635lfh3v7ideqkt35i3)

## SU_vm_master

不怎么会做vm题，没做出来

找到vm的位置，动调dump出vm的代码

```python
from ctypes import *
start = 0x555555574EB8
end = 0x555555578CB0
name = {
0x55555555d988:'func1',
0x55555555D9B0: 'mov1_addr',
0x55555555D9D8: 'mov2_addr',
0x55555555DA00: 'cmp_addr',
0x55555555DA28: 'func5_addr',
0x55555555DA50: 'func6_addr',
0x55555555DA78: 'func7_addr',
0x55555555DAA0: 'func8_add_addr',
0x55555555DAD0: 'func8_sub_addr',
0x55555555DB00: 'func8_and_addr',
0x55555555DB30: 'func8_or_addr',
0x55555555DB60: 'func8_xor_addr',
0x55555555DB90: 'func8_lshift_addr',
0x55555555DBC0: 'func8_rshift_addr'
}
arg_num = {
0x55555555d988: 3,
0x55555555D9B0: 4,
0x55555555D9D8: 4,
0x55555555DA00: 3,
0x55555555DA28: 2,
0x55555555DA50: 1,
0x55555555DA78: 0,
0x55555555DAA0: 4,
0x55555555DAD0: 4,
0x55555555DB00: 4,
0x55555555DB30: 4,
0x55555555DB60: 4,
0x55555555DB90: 4,
0x55555555DBC0: 4
}
now = start
while now <= end:
    size = get_qword(now)
    func_addr = get_qword(now+8)
    args = []
    for i in range(arg_num[func_addr]):
        args.append(c_int64(get_qword(now+16+i*8)).value)
    print(name[func_addr],args)
    if size == 0x31:
        now+=6*8
    else:
        now+=4*8
```

然后尝试用Python还原

```python
reg = [0 for _ in range(35)]
stack = [0 for _ in range(22000)]  # 第三个参数，mov才有

magic = [0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62, 0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35, 0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1, 0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51, 0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84, 0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48, 0xC6, 0xBA, 0xB1, 0xA3, 0x50, 0x33, 0xAA, 0x56, 0x97, 0x91, 0x7D, 0x67, 0xDC, 0x22, 0x70, 0xB2, 0x15, 0x0E, 0x07, 0x00, 0x31, 0x2A, 0x23, 0x1C, 0x4D, 0x46, 0x3F, 0x38, 0x69, 0x62, 0x5B, 0x54, 0x85, 0x7E, 0x77, 0x70, 0xA1, 0x9A, 0x93, 0x8C, 0xBD, 0xB6, 0xAF, 0xA8, 0xD9, 0xD2, 0xCB, 0xC4, 0xF5, 0xEE, 0xE7, 0xE0, 0x11, 0x0A, 0x03, 0xFC, 0x2D, 0x26, 0x1F, 0x18, 0x49, 0x42, 0x3B, 0x34, 0x65, 0x5E, 0x57, 0x50, 0x81, 0x7A, 0x73, 0x6C, 0x9D, 0x96, 0x8F, 0x88, 0xB9, 0xB2, 0xAB, 0xA4, 0xD5, 0xCE, 0xC7, 0xC0, 0xF1, 0xEA, 0xE3, 0xDC, 0x0D, 0x06, 0xFF, 0xF8, 0x29, 0x22, 0x1B, 0x14, 0x45, 0x3E, 0x37, 0x30, 0x61, 0x5A, 0x53, 0x4C, 0x7D, 0x76, 0x6F, 0x68, 0x99, 0x92, 0x8B, 0x84, 0xB5, 0xAE, 0xA7, 0xA0, 0xD1, 0xCA, 0xC3, 0xBC, 0xED, 0xE6, 0xDF, 0xD8, 0x09, 0x02, 0xFB, 0xF4, 0x25, 0x1E, 0x17, 0x10, 0x41, 0x3A, 0x33, 0x2C, 0x5D, 0x56, 0x4F, 0x48, 0x79, 0x72, 0x6B, 0x64, 0x73, 0x6F, 0x6D, 0x65, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x76, 0x65, 0x72, 0x79, 0x62, 0x61, 0x64, 0x73, 0x6F, 0x6D, 0x65, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x6E, 0x6F, 0x74, 0x67, 0x6F, 0x6F, 0x64]

for i in range(len(magic)):
    stack[i] = magic[i]

def func1(a1, a2, a3):
    if a1:
        print('reg[%d] = %d' % (a2, a3))
        reg[a2] = a3
    else:
        print('reg[%d] = reg[%d]' % (a2, a3))
        reg[a2] = reg[a3]

def mov1(a1, a2, a3, a4):
    if a1 == 1:
        print('reg[%d] = stack[%d+reg[%d]] => reg[%d] = (BYTE)stack[%d]' % (a2, a4, a3, a2, a4 + reg[a3]))
        reg[a2] = stack[a4 + reg[a3]] & 0xff
    if a1 == 4:
        print('reg[%d] = stack[%d+reg[%d]] => reg[%d] = (DWORD)stack[%d]' % (a2, a4, a3, a2, a4 + reg[a3]))
        reg[a2] = stack[a4 + reg[a3]] + 256 * stack[a4 + reg[a3] + 1] + 65536 * stack[a4 + reg[a3] + 2] + 16777216 * stack[a4 + reg[a3] + 3]
    if a1 == 8:
        print('reg[%d] = stack[%d+reg[%d]] => reg[%d] = (QWORD)stack[%d]' % (a2, a4, a3, a2, a4 + reg[a3]))
        reg[a2] = stack[a4 + reg[a3]] + 256 * stack[a4 + reg[a3] + 1] + 65536 * stack[a4 + reg[a3] + 2] + 16777216 * stack[a4 + reg[a3] + 3] + 4294967296 * stack[a4 + reg[a3] + 4] + 1099511627776 * stack[a4 + reg[a3] + 5] + 281474976710656 * stack[a4 + reg[a3] + 6] + 72057594037927936 * stack[a4 + reg[a3] + 7]

def mov2(a1, a2, a3, a4):
    if a1 == 1:
        print('stack[%d+reg[%d]] = reg[%d] => (BYTE)stack[%d] = reg[%d]' % (a4, a3, a2, a4 + reg[a3], a2))
        stack[a4 + reg[a3]] = reg[a2] & 0xff
    if a1 == 4:
        print('stack[%d+reg[%d]] = reg[%d] => (DWORD)stack[%d] = reg[%d]' % (a4, a3, a2, a4 + reg[a3], a2))
        stack[a4 + reg[a3]] = reg[a2] & 0xff
        stack[a4 + reg[a3] + 1] = (reg[a2] >> 8) & 0xff
        stack[a4 + reg[a3] + 2] = (reg[a2] >> 16) & 0xff
        stack[a4 + reg[a3] + 3] = (reg[a2] >> 24) & 0xff

    if a1 == 8:
        print('stack[%d+reg[%d]] = reg[%d] => (QWORD)stack[%d] = reg[%d]' % (a4, a3, a2, a4 + reg[a3], a2))
        stack[a4 + reg[a3]] = reg[a2] & 0xff
        stack[a4 + reg[a3] + 1] = (reg[a2] >> 8) & 0xff
        stack[a4 + reg[a3] + 2] = (reg[a2] >> 16) & 0xff
        stack[a4 + reg[a3] + 3] = (reg[a2] >> 24) & 0xff
        stack[a4 + reg[a3] + 4] = (reg[a2] >> 32) & 0xff
        stack[a4 + reg[a3] + 5] = (reg[a2] >> 40) & 0xff
        stack[a4 + reg[a3] + 6] = (reg[a2] >> 48) & 0xff
        stack[a4 + reg[a3] + 7] = (reg[a2] >> 56) & 0xff

def cmp(a1, a2, a3):
    if a1:
        print('cmp(%d, reg[%d])' % (a3, a2))
        if a3 == reg[a2]:
            reg[33] = 1
        elif a3 > reg[a2]:
            reg[33] = 2
        else:
            reg[33] = 0
    else:
        print('cmp(reg[%d], reg[%d])' % (a3, a2))
        if reg[a3] == reg[a2]:
            reg[33] = 1
        elif reg[a3] > reg[a2]:
            reg[33] = 2
        else:
            reg[33] = 0

def func5(a1, a2):  # 类似jmp
    if a2 == 0:
        print('jmp %d' % a1)
        reg[32] = a1
    elif a2 == 1:
        print('jmp %d if equal' % a1)
        if reg[33] & 1 != 0:
            reg[32] = a1
    elif a2 == 2:
        print('jmp %d if not equal' % a1)
        if reg[33] & 1 == 0:
            reg[32] = a1
    elif a2 == 3:
        print('jmp %d if greater' % a1)
        if reg[33] & 2 != 0:
            reg[32] = a1
    elif a2 == 4:
        print('jmp %d if greater or equal' % a1)
        if reg[33] & 3 != 0:
            reg[32] = a1
    elif a2 == 5:
        print('jmp %d if smaller' % a1)
        if reg[33] & 3 == 0:
            reg[32] = a1
    elif a2 == 6:
        print('jmp %d if smaller or equal' % a1)
        if (reg[33] & 3 == 0) or (reg[33] & 1 != 0):
            reg[32] = a1

def func6(a1):
    print('call %d save ret in reg[30]' % a1)
    reg[30] = reg[32]
    reg[32] = a1

def func7():
    print('ret %d' % reg[30])
    reg[32] = reg[30]

def func8_add(a1, a2, a3, a4):
    if a1:
        print('reg[%d] = reg[%d] + %d' % (a2, a3, a4))
        reg[a2] = reg[a3] + a4
    else:
        print('reg[%d] = reg[%d] + reg[%d]' % (a2, a3, a4))
        reg[a2] = reg[a3] + reg[a4]

def func8_sub(a1, a2, a3, a4):
    if a1:
        print('reg[%d] = reg[%d] - %d' % (a2, a3, a4))
        reg[a2] = reg[a3] - a4
    else:
        print('reg[%d] = reg[%d] - reg[%d]' % (a2, a3, a4))
        reg[a2] = reg[a3] - reg[a4]

def func8_and(a1, a2, a3, a4):
    if a1:
        print('reg[%d] = reg[%d] & %d' % (a2, a3, a4))
        reg[a2] = reg[a3] & a4
    else:
        print('reg[%d] = reg[%d] & reg[%d]' % (a2, a3, a4))
        reg[a2] = reg[a3] & reg[a4]

def func8_or(a1, a2, a3, a4):
    if a1:
        print('reg[%d] = reg[%d] | %d' % (a2, a3, a4))
        reg[a2] = reg[a3] | a4
    else:
        print('reg[%d] = reg[%d] | reg[%d]' % (a2, a3, a4))
        reg[a2] = reg[a3] | reg[a4]

def func8_xor(a1, a2, a3, a4):
    if a1:
        print('reg[%d] = reg[%d] ^ %d' % (a2, a3, a4))
        reg[a2] = reg[a3] ^ a4
    else:
        print('reg[%d] = reg[%d] ^ reg[%d]' % (a2, a3, a4))
        reg[a2] = reg[a3] ^ reg[a4]

def func8_shl(a1, a2, a3, a4):
    if a1:
        print('reg[%d] = reg[%d] << %d' % (a2, a3, a4))
        reg[a2] = (reg[a3] << a4) & 0xffffffffffffffff
    else:
        print('reg[%d] = reg[%d] << reg[%d]' % (a2, a3, a4))
        reg[a2] = (reg[a3] << reg[a4]) & 0xffffffffffffffff

def func8_shr(a1, a2, a3, a4):
    if a1:
        print('reg[%d] = reg[%d] >> %d' % (a2, a3, a4))
        reg[a2] = reg[a3] >> a4
    else:
        print('reg[%d] = reg[%d] >> reg[%d]' % (a2, a3, a4))
        reg[a2] = reg[a3] >> reg[a4]

program = [
"func1(0,3,0)",
"func8_add(0,1,1,2)",
"func8_xor(0,0,0,0)",
"mov1(1,2,1,0)",
"func8_shl(1,2,2,16)",
"func8_or(0,0,0,2)",
"mov1(1,2,1,1)",
"func8_shl(1,2,2,8)",
"func8_or(0,0,0,2)",
"mov1(1,2,1,2)",
"func8_shl(1,2,2,0)",
"func8_or(0,0,0,2)",
"mov1(1,2,1,3)",
"func8_shl(1,2,2,24)",
"func8_or(0,0,0,2)",
"mov2(4,0,3,0)",
"func7()",
"func8_add(0,1,1,2)",
"func8_shr(1,2,0,16)",
"mov2(1,2,1,0)",
"func8_shr(1,2,0,8)",
"mov2(1,2,1,1)",
"func8_shr(1,2,0,0)",
"mov2(1,2,1,2)",
"func8_shr(1,2,0,24)",
"mov2(1,2,1,3)",
"func7()",
"func8_and(1,0,0,0xFFFFFFFF)",
"func8_and(1,1,1,31)",
"func8_shl(0,2,0,1)",
"func1(1,3,32)",
"func8_sub(0,1,3,1)",
"func8_shr(0,0,0,1)",
"func8_or(0,0,0,2)",
"func8_and(1,0,0,0xFFFFFFFF)",
"func7()",
"func8_and(1,0,0,255)",
"func1(1,1,0)",
"func8_add(0,0,0,1)",
"mov1(1,0,0,0)",
"func7()",
"mov2(8,30,31,-8)",
"mov2(8,29,31,-16)",
"mov2(8,19,31,-24)",
"func8_sub(1,29,31,32)",
"func8_sub(1,31,31,96)",
"func8_sub(1,1,29,16)",
"func8_xor(0,2,2,2)",
"func6(17)",
"mov1(1,0,29,-16)",
"func6(36)",
"mov2(1,0,29,-32)",
"mov1(1,0,29,-15)",
"func6(36)",
"mov2(1,0,29,-31)",
"mov1(1,0,29,-14)",
"func6(36)",
"mov2(1,0,29,-30)",
"mov1(1,0,29,-13)",
"func6(36)",
"mov2(1,0,29,-29)",
"func8_sub(1,0,29,48)",
"func8_sub(1,1,29,32)",
"func1(1,2,0)",
"func6(0)",
"mov1(4,19,29,-48)",
"mov1(4,0,29,-48)",
"func1(1,1,2)",
"func6(27)",
"func8_xor(0,19,19,0)",
"mov1(4,0,29,-48)",
"func1(1,1,10)",
"func6(27)",
"func8_xor(0,19,19,0)",
"mov1(4,0,29,-48)",
"func1(1,1,18)",
"func6(27)",
"func8_xor(0,19,19,0)",
"mov1(4,0,29,-48)",
"func1(1,1,24)",
"func6(27)",
"func8_xor(0,0,19,0)",
"func8_add(1,31,31,96)",
"mov1(8,19,31,-24)",
"mov1(8,29,31,-16)",
"mov1(8,30,31,-8)",
"func7()",
"mov2(8,30,31,-8)",
"mov2(8,0,31,-16)",
"func8_sub(1,31,31,16)",
"func8_xor(0,0,1,2)",
"func8_xor(0,0,0,3)",
"func8_xor(0,0,0,4)",
"func6(41)",
"func8_add(1,31,31,16)",
"mov1(8,1,31,-16)",
"mov1(8,30,31,-8)",
"func8_xor(0,0,0,1)",
"func7()",
"mov2(8,30,31,-8)",
"mov2(8,29,31,-16)",
"mov2(8,19,31,-24)",
"func8_sub(1,29,31,32)",
"func8_sub(1,31,31,96)",
"func8_sub(1,1,29,16)",
"func8_xor(0,2,2,2)",
"func6(17)",
"mov1(1,0,29,-16)",
"func6(36)",
"mov2(1,0,29,-32)",
"mov1(1,0,29,-15)",
"func6(36)",
"mov2(1,0,29,-31)",
"mov1(1,0,29,-14)",
"func6(36)",
"mov2(1,0,29,-30)",
"mov1(1,0,29,-13)",
"func6(36)",
"mov2(1,0,29,-29)",
"func8_sub(1,0,29,48)",
"func8_sub(1,1,29,32)",
"func1(1,2,0)",
"func6(0)",
"mov1(4,19,29,-48)",
"mov1(4,0,29,-48)",
"func1(1,1,13)",
"func6(27)",
"func8_xor(0,19,19,0)",
"mov1(4,0,29,-48)",
"func1(1,1,23)",
"func6(27)",
"func8_xor(0,0,19,0)",
"func8_add(1,31,31,96)",
"mov1(8,19,31,-24)",
"mov1(8,29,31,-16)",
"mov1(8,30,31,-8)",
"func7()",
"mov2(8,30,31,-8)",
"mov2(8,29,31,-16)",
"mov2(8,1,31,-24)",
"mov2(8,0,31,-32)",
"func8_sub(1,29,31,32)",
"func8_sub(1,31,31,256)",
"func8_sub(1,0,29,16)",
"mov1(8,1,29,8)",
"func1(1,2,0)",
"func6(0)",
"func8_sub(1,0,29,12)",
"mov1(8,1,29,8)",
"func1(1,2,4)",
"func6(0)",
"func8_sub(1,0,29,8)",
"mov1(8,1,29,8)",
"func1(1,2,8)",
"func6(0)",
"func8_sub(1,0,29,4)",
"mov1(8,1,29,8)",
"func1(1,2,12)",
"func6(0)",
"func8_sub(1,0,29,16)",
"func1(1,1,256)",
"func1(0,2,31)",
"mov1(4,3,0,0)",
"mov1(4,4,1,0)",
"func8_xor(0,3,3,4)",
"mov2(4,3,2,0)",
"mov1(4,3,0,4)",
"mov1(4,4,1,4)",
"func8_xor(0,3,3,4)",
"mov2(4,3,2,4)",
"mov1(4,3,0,8)",
"mov1(4,4,1,8)",
"func8_xor(0,3,3,4)",
"mov2(4,3,2,8)",
"mov1(4,3,0,12)",
"mov1(4,4,1,12)",
"func8_xor(0,3,3,4)",
"mov2(4,3,2,12)",
"func1(1,0,0)",
"mov2(4,0,29,-32)",
"mov1(4,0,29,-32)",
"cmp(1,0,32)",
"func5(208,6)",
"func8_shl(1,0,0,2)",
"func8_add(0,1,31,0)",
"func1(1,2,272)",
"func8_add(0,2,2,0)",
"mov1(4,2,2,0)",
"mov1(4,0,1,4)",
"func8_xor(0,0,0,2)",
"mov1(4,2,1,8)",
"func8_xor(0,0,0,2)",
"mov1(4,2,1,12)",
"func8_xor(0,0,0,2)",
"func6(99)",
"mov1(4,1,29,-32)",
"func8_shl(1,1,1,2)",
"func8_add(0,2,31,1)",
"mov1(4,3,2,0)",
"func8_xor(0,0,0,3)",
"mov2(4,0,2,16)",
"mov1(8,2,29,0)",
"func8_add(0,2,2,1)",
"mov2(4,0,2,0)",
"mov1(4,0,29,-32)",
"func8_add(1,0,0,1)",
"mov2(4,0,29,-32)",
"func5(180,0)",
"func8_add(1,31,31,256)",
"mov1(8,29,31,-16)",
"mov1(8,30,31,-8)",
"func7()",
"mov2(8,30,31,-8)",
"mov2(8,29,31,-16)",
"mov2(8,2,31,-32)",
"mov2(8,1,31,-40)",
"mov2(8,0,31,-48)",
"func8_sub(1,29,31,48)",
"func8_sub(1,31,31,256)",
"func8_add(1,0,31,0)",
"mov1(8,1,29,8)",
"func1(1,2,0)",
"func6(0)",
"func8_add(1,0,31,4)",
"mov1(8,1,29,8)",
"func1(1,2,4)",
"func6(0)",
"func8_add(1,0,31,8)",
"mov1(8,1,29,8)",
"func1(1,2,8)",
"func6(0)",
"func8_add(1,0,31,12)",
"mov1(8,1,29,8)",
"func1(1,2,12)",
"func6(0)",
"func1(1,0,0)",
"mov2(4,0,29,-16)",
"mov1(4,4,29,-16)",
"cmp(1,4,32)",
"func5(262,6)",
"func8_shl(1,4,4,2)",
"func8_add(0,3,31,4)",
"mov1(8,0,29,0)",
"func8_add(0,0,0,4)",
"mov1(4,4,0,0)",
"mov1(4,0,3,0)",
"mov1(4,1,3,4)",
"mov1(4,2,3,8)",
"mov1(4,3,3,12)",
"func6(87)",
"func1(1,1,0xDEAD0000)",
"func1(1,2,0xBEEF)",
"func8_xor(0,1,1,2)",
"func8_xor(0,0,0,1)",
"mov1(4,4,29,-16)",
"func8_shl(1,4,4,2)",
"func8_add(0,4,31,4)",
"mov2(4,0,4,16)",
"mov1(4,0,29,-16)",
"func8_add(1,0,0,1)",
"mov2(4,0,29,-16)",
"func5(237,0)",
"mov1(4,0,31,140)",
"mov1(8,1,29,16)",
"func1(1,2,0)",
"func6(17)",
"mov1(4,0,31,136)",
"mov1(8,1,29,16)",
"func1(1,2,4)",
"func6(17)",
"mov1(4,0,31,132)",
"mov1(8,1,29,16)",
"func1(1,2,8)",
"func6(17)",
"mov1(4,0,31,128)",
"mov1(8,1,29,16)",
"func1(1,2,12)",
"func6(17)",
"func8_add(1,31,31,256)",
"mov1(8,29,31,-16)",
"mov1(8,30,31,-8)",
"func7()",
"mov2(8,30,31,-8)",
"mov2(8,29,31,-16)",
"mov2(4,2,31,-32)",
"mov2(8,1,31,-40)",
"mov2(8,0,31,-48)",
"func8_sub(1,29,31,48)",
"func8_sub(1,31,31,256)",
"func8_sub(1,0,29,16)",
"mov1(8,1,4,0)",
"mov2(8,1,0,0)",
"mov1(8,1,4,8)",
"mov2(8,1,0,8)",
"func1(0,0,31)",
"func1(0,1,3)",
"func6(137)",
"mov1(4,1,29,16)",
"cmp(1,1,0)",
"func5(331,1)",
"func8_sub(1,0,29,16)",
"mov1(8,1,29,8)",
"func8_sub(1,2,29,32)",
"mov1(8,3,0,0)",
"mov1(8,4,1,0)",
"func8_xor(0,3,3,4)",
"mov2(8,3,2,0)",
"mov1(8,3,0,8)",
"mov1(8,4,1,8)",
"func8_xor(0,3,3,4)",
"mov2(8,3,2,8)",
"func1(0,0,31)",
"func8_sub(1,1,29,32)",
"mov1(8,2,29,0)",
"func6(212)",
"mov1(8,0,29,0)",
"func8_sub(1,1,29,16)",
"mov1(8,2,0,0)",
"mov2(8,2,1,0)",
"mov1(8,2,0,8)",
"mov2(8,2,1,8)",
"mov1(4,0,29,16)",
"func8_sub(1,0,0,16)",
"mov2(4,0,29,16)",
"mov1(8,0,29,8)",
"func8_add(1,0,0,16)",
"mov2(8,0,29,8)",
"mov1(8,0,29,0)",
"func8_add(1,0,0,16)",
"mov2(8,0,29,0)",
"func5(297,0)",
"func8_add(1,31,31,256)",
"mov1(8,29,31,-16)",
"mov1(8,30,31,-8)",
"func7()",
"mov2(8,30,31,-8)",
"mov2(8,29,31,-16)",
"func8_sub(1,31,31,16)",
"func1(1,0,2048)",
"func1(1,1,2048)",
"func1(1,2,32)",
"func1(1,3,400)",
"func1(1,4,416)",
"func6(282)",
"func8_add(1,31,31,16)",
"mov1(8,29,31,-16)",
"mov1(8,30,31,-8)",
"func7()",
"func7()"
]


if __name__ == '__main__':
    for i in range(2048, 2048+32):
        stack[i] = 0x31   # input
    for i in range(256, 600):
        print(i, hex(stack[i]))
    reg[31] = 16376
    reg[32] = 335
    ip = 335
    reg[30] = 0xDEADBEEF
    while ip != 0xDEADBEEF:
        print(ip, end=' ')
        cmd = program[ip]
        reg[32] = ip + 1
        eval(cmd)
        ip = reg[32]

    for i in range(2048, 2048+32):
        print(hex(stack[i]), end=' ')   # output

'''
reg[0] rax
reg[1] rbx
reg[2] rcx
reg[3] rdx
reg[4] rsi
reg[19] rdi
reg[29] rbp
reg[30] 返回地址
reg[31] rsp
reg[32] rip
reg[33] cmp结果
'''
```

能打印出整个的运行流程。加密结果跟程序的一样。刚开始没有复制stack的内容，导致结果不一样，发现后复制过来就可以了。

然后修改一下这个脚本，翻译dump出来的vm

```
0   rdx = rax
1   rbx = rbx + rcx
2   rax = rax ^ rax
3   rcx = (BYTE) stack[0+rbx]
4   rcx = rcx << 16
5   rax = rax | rcx
6   rcx = (BYTE) stack[1+rbx]
7   rcx = rcx << 8
8   rax = rax | rcx
9   rcx = (BYTE) stack[2+rbx]
10  rcx = rcx << 0
11  rax = rax | rcx
12  rcx = (BYTE) stack[3+rbx]
13  rcx = rcx << 24
14  rax = rax | rcx
15  (DWORD) stack[0+rdx] = rax
16  ret


17  rbx = rbx + rcx
18  rcx = rax >> 16
19  (BYTE) stack[0+rbx] = rcx
20  rcx = rax >> 8
21  (BYTE) stack[1+rbx] = rcx
22  rcx = rax >> 0
23  (BYTE) stack[2+rbx] = rcx
24  rcx = rax >> 24
25  (BYTE) stack[3+rbx] = rcx
26  ret


27  rax = rax & 4294967295
28  rbx = rbx & 31
29  rcx = rax << rbx
30  rdx = 32
31  rbx = rdx - rbx
32  rax = rax >> rbx
33  rax = rax | rcx
34  rax = rax & 4294967295
35  ret


36  rax = rax & 255
37  rbx = 0
38  rax = rax + rbx
39  rax = (BYTE) stack[0+rax]
40  ret


41  (QWORD) stack[-8+rsp] = rip
42  (QWORD) stack[-16+rsp] = rbp
43  (QWORD) stack[-24+rsp] = rdi
44  rbp = rsp - 32
45  rsp = rsp - 96
46  rbx = rbp - 16
47  rcx = rcx ^ rcx
48  call 17
49  rax = (BYTE) stack[-16+rbp]
50  call 36
51  (BYTE) stack[-32+rbp] = rax
52  rax = (BYTE) stack[-15+rbp]
53  call 36
54  (BYTE) stack[-31+rbp] = rax
55  rax = (BYTE) stack[-14+rbp]
56  call 36
57  (BYTE) stack[-30+rbp] = rax
58  rax = (BYTE) stack[-13+rbp]
59  call 36
60  (BYTE) stack[-29+rbp] = rax
61  rax = rbp - 48
62  rbx = rbp - 32
63  rcx = 0
64  call 0
65  rdi = (DWORD) stack[-48+rbp]
66  rax = (DWORD) stack[-48+rbp]
67  rbx = 2
68  call 27
69  rdi = rdi ^ rax
70  rax = (DWORD) stack[-48+rbp]
71  rbx = 10
72  call 27
73  rdi = rdi ^ rax
74  rax = (DWORD) stack[-48+rbp]
75  rbx = 18
76  call 27
77  rdi = rdi ^ rax
78  rax = (DWORD) stack[-48+rbp]
79  rbx = 24
80  call 27
81  rax = rdi ^ rax
82  rsp = rsp + 96
83  rdi = (QWORD) stack[-24+rsp]
84  rbp = (QWORD) stack[-16+rsp]
85  rip = (QWORD) stack[-8+rsp]
86  ret


87  (QWORD) stack[-8+rsp] = rip
88  (QWORD) stack[-16+rsp] = rax
89  rsp = rsp - 16
90  rax = rbx ^ rcx
91  rax = rax ^ rdx
92  rax = rax ^ rsi
93  call 41
94  rsp = rsp + 16
95  rbx = (QWORD) stack[-16+rsp]
96  rip = (QWORD) stack[-8+rsp]
97  rax = rax ^ rbx
98  ret


99  (QWORD) stack[-8+rsp] = rip
100 (QWORD) stack[-16+rsp] = rbp
101 (QWORD) stack[-24+rsp] = rdi
102 rbp = rsp - 32
103 rsp = rsp - 96
104 rbx = rbp - 16
105 rcx = rcx ^ rcx
106 call 17
107 rax = (BYTE) stack[-16+rbp]
108 call 36
109 (BYTE) stack[-32+rbp] = rax
110 rax = (BYTE) stack[-15+rbp]
111 call 36
112 (BYTE) stack[-31+rbp] = rax
113 rax = (BYTE) stack[-14+rbp]
114 call 36
115 (BYTE) stack[-30+rbp] = rax
116 rax = (BYTE) stack[-13+rbp]
117 call 36
118 (BYTE) stack[-29+rbp] = rax
119 rax = rbp - 48
120 rbx = rbp - 32
121 rcx = 0
122 call 0
123 rdi = (DWORD) stack[-48+rbp]
124 rax = (DWORD) stack[-48+rbp]
125 rbx = 13
126 call 27
127 rdi = rdi ^ rax
128 rax = (DWORD) stack[-48+rbp]
129 rbx = 23
130 call 27
131 rax = rdi ^ rax
132 rsp = rsp + 96
133 rdi = (QWORD) stack[-24+rsp]
134 rbp = (QWORD) stack[-16+rsp]
135 rip = (QWORD) stack[-8+rsp]
136 ret


137 (QWORD) stack[-8+rsp] = rip
138 (QWORD) stack[-16+rsp] = rbp
139 (QWORD) stack[-24+rsp] = rbx
140 (QWORD) stack[-32+rsp] = rax
141 rbp = rsp - 32
142 rsp = rsp - 256
143 rax = rbp - 16
144 rbx = (QWORD) stack[8+rbp]
145 rcx = 0
146 call 0
147 rax = rbp - 12
148 rbx = (QWORD) stack[8+rbp]
149 rcx = 4
150 call 0
151 rax = rbp - 8
152 rbx = (QWORD) stack[8+rbp]
153 rcx = 8
154 call 0
155 rax = rbp - 4
156 rbx = (QWORD) stack[8+rbp]
157 rcx = 12
158 call 0
159 rax = rbp - 16
160 rbx = 256
161 rcx = rsp
162 rdx = (DWORD) stack[0+rax]
163 rsi = (DWORD) stack[0+rbx]
164 rdx = rdx ^ rsi
165 (DWORD) stack[0+rcx] = rdx
166 rdx = (DWORD) stack[4+rax]
167 rsi = (DWORD) stack[4+rbx]
168 rdx = rdx ^ rsi
169 (DWORD) stack[4+rcx] = rdx
170 rdx = (DWORD) stack[8+rax]
171 rsi = (DWORD) stack[8+rbx]
172 rdx = rdx ^ rsi
173 (DWORD) stack[8+rcx] = rdx
174 rdx = (DWORD) stack[12+rax]
175 rsi = (DWORD) stack[12+rbx]
176 rdx = rdx ^ rsi
177 (DWORD) stack[12+rcx] = rdx
178 rax = 0
179 (DWORD) stack[-32+rbp] = rax
180 rax = (DWORD) stack[-32+rbp]
181 cmp(32, rax)
182 jmp 208 if smaller or equal
183 rax = rax << 2
184 rbx = rsp + rax
185 rcx = 272
186 rcx = rcx + rax
187 rcx = (DWORD) stack[0+rcx]
188 rax = (DWORD) stack[4+rbx]
189 rax = rax ^ rcx
190 rcx = (DWORD) stack[8+rbx]
191 rax = rax ^ rcx
192 rcx = (DWORD) stack[12+rbx]
193 rax = rax ^ rcx
194 call 99
195 rbx = (DWORD) stack[-32+rbp]
196 rbx = rbx << 2
197 rcx = rsp + rbx
198 rdx = (DWORD) stack[0+rcx]
199 rax = rax ^ rdx
200 (DWORD) stack[16+rcx] = rax
201 rcx = (QWORD) stack[0+rbp]
202 rcx = rcx + rbx
203 (DWORD) stack[0+rcx] = rax
204 rax = (DWORD) stack[-32+rbp]
205 rax = rax + 1
206 (DWORD) stack[-32+rbp] = rax
207 jmp 180
208 rsp = rsp + 256
209 rbp = (QWORD) stack[-16+rsp]
210 rip = (QWORD) stack[-8+rsp]
211 ret


212 (QWORD) stack[-8+rsp] = rip
213 (QWORD) stack[-16+rsp] = rbp
214 (QWORD) stack[-32+rsp] = rcx
215 (QWORD) stack[-40+rsp] = rbx
216 (QWORD) stack[-48+rsp] = rax
217 rbp = rsp - 48
218 rsp = rsp - 256
219 rax = rsp + 0
220 rbx = (QWORD) stack[8+rbp]
221 rcx = 0
222 call 0
223 rax = rsp + 4
224 rbx = (QWORD) stack[8+rbp]
225 rcx = 4
226 call 0
227 rax = rsp + 8
228 rbx = (QWORD) stack[8+rbp]
229 rcx = 8
230 call 0
231 rax = rsp + 12
232 rbx = (QWORD) stack[8+rbp]
233 rcx = 12
234 call 0
235 rax = 0
236 (DWORD) stack[-16+rbp] = rax
237 rsi = (DWORD) stack[-16+rbp]
238 cmp(32, rsi)
239 jmp 262 if smaller or equal
240 rsi = rsi << 2
241 rdx = rsp + rsi
242 rax = (QWORD) stack[0+rbp]
243 rax = rax + rsi
244 rsi = (DWORD) stack[0+rax]
245 rax = (DWORD) stack[0+rdx]
246 rbx = (DWORD) stack[4+rdx]
247 rcx = (DWORD) stack[8+rdx]
248 rdx = (DWORD) stack[12+rdx]
249 call 87
250 rbx = 3735879680
251 rcx = 48879
252 rbx = rbx ^ rcx
253 rax = rax ^ rbx
254 rsi = (DWORD) stack[-16+rbp]
255 rsi = rsi << 2
256 rsi = rsp + rsi
257 (DWORD) stack[16+rsi] = rax
258 rax = (DWORD) stack[-16+rbp]
259 rax = rax + 1
260 (DWORD) stack[-16+rbp] = rax
261 jmp 237
262 rax = (DWORD) stack[140+rsp]
263 rbx = (QWORD) stack[16+rbp]
264 rcx = 0
265 call 17
266 rax = (DWORD) stack[136+rsp]
267 rbx = (QWORD) stack[16+rbp]
268 rcx = 4
269 call 17
270 rax = (DWORD) stack[132+rsp]
271 rbx = (QWORD) stack[16+rbp]
272 rcx = 8
273 call 17
274 rax = (DWORD) stack[128+rsp]
275 rbx = (QWORD) stack[16+rbp]
276 rcx = 12
277 call 17
278 rsp = rsp + 256
279 rbp = (QWORD) stack[-16+rsp]
280 rip = (QWORD) stack[-8+rsp]
281 ret


282 (QWORD) stack[-8+rsp] = rip
283 (QWORD) stack[-16+rsp] = rbp
284 (DWORD) stack[-32+rsp] = rcx
285 (QWORD) stack[-40+rsp] = rbx
286 (QWORD) stack[-48+rsp] = rax   本质上还是通过栈来传参？
287 rbp = rsp - 48
288 rsp = rsp - 256
289 rax = rbp - 16
290 rbx = (QWORD) stack[0+rsi]
291 (QWORD) stack[0+rax] = rbx
292 rbx = (QWORD) stack[8+rsi]
293 (QWORD) stack[8+rax] = rbx
294 rax = rsp
295 rbx = rdx
296 call 137
297 rbx = (DWORD) stack[16+rbp]
298 cmp(0, rbx)
299 jmp 331 if equal
300 rax = rbp - 16
301 rbx = (QWORD) stack[8+rbp]
302 rcx = rbp - 32
303 rdx = (QWORD) stack[0+rax]
304 rsi = (QWORD) stack[0+rbx]
305 rdx = rdx ^ rsi
306 (QWORD) stack[0+rcx] = rdx
307 rdx = (QWORD) stack[8+rax]
308 rsi = (QWORD) stack[8+rbx]
309 rdx = rdx ^ rsi
310 (QWORD) stack[8+rcx] = rdx
311 rax = rsp
312 rbx = rbp - 32
313 rcx = (QWORD) stack[0+rbp]
314 call 212
315 rax = (QWORD) stack[0+rbp]
316 rbx = rbp - 16
317 rcx = (QWORD) stack[0+rax]
318 (QWORD) stack[0+rbx] = rcx
319 rcx = (QWORD) stack[8+rax]
320 (QWORD) stack[8+rbx] = rcx
321 rax = (DWORD) stack[16+rbp]
322 rax = rax - 16
323 (DWORD) stack[16+rbp] = rax
324 rax = (QWORD) stack[8+rbp]
325 rax = rax + 16
326 (QWORD) stack[8+rbp] = rax
327 rax = (QWORD) stack[0+rbp]
328 rax = rax + 16
329 (QWORD) stack[0+rbp] = rax
330 jmp 297
331 rsp = rsp + 256
332 rbp = (QWORD) stack[-16+rsp]
333 rip = (QWORD) stack[-8+rsp]
334 ret


335 (QWORD) stack[-8+rsp] = rip
336 (QWORD) stack[-16+rsp] = rbp
337 rsp = rsp - 16
338 rax = 2048
339 rbx = 2048
340 rcx = 32
341 rdx = 400
342 rsi = 416
343 call 282
344 rsp = rsp + 16
345 rbp = (QWORD) stack[-16+rsp]
346 rip = (QWORD) stack[-8+rsp]
347 ret
348 ret
```

大概能看出点雏形了，但还是没能做出来。后来知道是魔改SM4算法后看了一下确实基本都能对的上，魔改的地方上面也能很明显看出来是0和17数据转换时位数做了些变换。

看了下补全的栈发现0-400 bytes都是SM4里面的常量，后面32bytes应该就是对应key和iv。可惜没发现常量，不然确定是SM4后对照源码估计逆起来会轻松些

## SU_minesweeper

看了下题目没做，队里其他人做了

给出个地图每格的数字说明该格附近9x9的雷数，要求找出雷的位置，然后将表示雷的01转成hex输入。开始想的是找网上的求解器，但是这题跟普通扫雷最大的不同就是数字下面也可能有雷，一般求解器做不到，需要自己写算法。又想了想这种条件的直接用约束求解器就行了。这里贴下官方wp的脚本

```python
#!/usr/bin/env python3

from z3 import *
import hashlib

problem = [
	[3, 4, -1, -1, -1, 5, -1, -1, -1, -1, -1, 4, 4, -1, -1, -1, -1, 2, -1, -1],
	[4, -1, 7, -1, -1, -1, 4, 6, 6, -1, -1, -1, -1, 6, 5, 6, 4, -1, 5, -1],
	[4, 7, -1, 8, -1, 6, -1, -1, 6, 6, 5, -1, -1, -1, -1, -1, 3, 3, -1, 3],
	[-1, 5, 6, 6, -1, -1, -1, -1, 4, 5, 4, 5, 7, 6, -1, -1, 4, -1, 2, 1],
	[-1, -1, -1, 3, 4, -1, -1, 5, 4, 3, -1, -1, 7, 4, 3, -1, -1, 1, 1, -1],
	[-1, 4, 3, -1, 2, -1, 4, 3, -1, -1, 2, -1, 5, 4, -1, -1, 2, 2, -1, -1],
	[4, -1, 4, -1, 3, 5, 6, -1, -1, 0, -1, -1, -1, 2, -1, -1, -1, 1, 4, -1],
	[-1, 7, 5, -1, -1, 3, 3, 2, -1, -1, 4, -1, -1, 5, 7, -1, 3, 2, 4, 4],
	[-1, 7, 5, 4, 3, -1, -1, 4, -1, 2, 4, 5, -1, -1, 6, 5, 4, -1, 2, -1],
	[-1, 7, 4, -1, -1, 3, -1, 4, 4, -1, -1, -1, -1, -1, -1, -1, 4, 3, 2, 2],
	[-1, -1, 2, 4, 3, 5, -1, -1, 5, -1, 4, -1, 6, -1, -1, 6, -1, -1, -1, -1],
	[3, 3, -1, 4, -1, -1, -1, -1, -1, 6, -1, 6, 6, -1, 7, 6, 4, -1, 4, 3],
	[-1, 4, 3, 5, 4, -1, -1, -1, -1, -1, -1, -1, 4, 6, 7, -1, -1, 4, -1, -1],
	[-1, 7, -1, 5, -1, 5, -1, -1, 6, 7, 7, -1, 5, 6, 6, -1, -1, 2, 4, 4],
	[-1, -1, -1, -1, -1, 6, -1, -1, 7, 7, 6, -1, 6, -1, -1, -1, -1, 3, -1, 3],
	[5, -1, 7, -1, 5, -1, 6, -1, 5, -1, -1, 7, 8, -1, -1, 3, -1, 3, -1, -1],
	[-1, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1, 6, 5, 3, -1, 4, 5, 5, 3, -1],
	[-1, 6, 5, 5, 6, -1, 6, 5, 2, 4, 3, 4, -1, -1, 3, 4, 4, 6, 5, -1],
	[3, -1, 5, 5, 5, -1, -1, 5, -1, -1, 4, -1, -1, 4, -1, 7, 7, 8, 6, -1],
	[-1, -1, -1, 5, -1, -1, -1, 4, -1, 3, -1, 3, -1, -1, -1, -1, -1, -1, 5, 3]
]

def var_at(y, x):
	if y < 0 or x < 0 or y >= 20 or x >= 20: return 0
	return blocks[y][x]

def sum_at(y, x):
	s = 0
	for dy in range(-1, 2):
		for dx in range(-1, 2):
			s += var_at(y + dy, x + dx)
	return s

blocks = [[ Int('x_%d_%d' % (y, x)) for x in range(20) ] for y in range(20) ]


solver = Solver()
for line in blocks:
	for block in line:
		solver.add(Or(block == 0, block == 1))

for y in range(20):
	for x in range(20):
		if problem[y][x] != -1:
			solver.add(sum_at(y, x) == problem[y][x])

print('checking')
assert solver.check() == sat
model = solver.model()
# print(model)

answer = bytearray(400 // 8)
for y in range(20):
	print('|', end='')
	for x in range(20):
		v = model[var_at(y, x)].as_long()
		if v:
			print('#', end='')
		else:
			print(' ', end='')
		answer[(20 * y + x) // 8] |= v << ((20 * y + x) % 8)
	print('|')

answer = answer.hex()
answer = answer.translate(str.maketrans('0123456789abcdef', 'abcdef0123456789'))
print(answer)
# f57503596fb80f955fa5cad3cb282aa18ac62922a1981ea7b53b07a30709b508f3176601154250d509b7bee0f2170b898617

print('SUCTF{%s}' % hashlib.md5(answer.encode()).hexdigest())
# SUCTF{d661b98e4241de7423ef2d953098329d}
```

