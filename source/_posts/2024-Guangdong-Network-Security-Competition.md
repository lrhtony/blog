---
title: 第三届广东大学生网络安全攻防竞赛 Reversse
comments: true
date: 2024-05-12 19:12:43
tags:
  - CTF
categories:
  - 技术
---

无力吐槽
## re1
双击打开程序，卧槽闪退？！留意到有输出！![image-20240513233527257](https://img.0a0.moe/blog/2024/05/12/%E7%AC%AC%E4%B8%89%E5%B1%8A%E5%B9%BF%E4%B8%9C%E5%A4%A7%E5%AD%A6%E7%94%9F%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%94%BB%E9%98%B2%E7%AB%9E%E8%B5%9B-reversse/1ed5051388233971012b64095ecf6eafa9fb0fecd8fae30421d407b9c53ccfef.webp)

看看代码

![image-20240513233623216](https://img.0a0.moe/blog/2024/05/12/%E7%AC%AC%E4%B8%89%E5%B1%8A%E5%B9%BF%E4%B8%9C%E5%A4%A7%E5%AD%A6%E7%94%9F%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%94%BB%E9%98%B2%E7%AB%9E%E8%B5%9B-reversse/a063727dac9f95d3dd57b55705549f0d3f18a9b4a5b5330f44cc39e20afa2a53.webp)

？？？？？？？？？？？？？？？？？？？？？？？？？？？？？

还真没东西。留意到`0x401190`有个函数结构，创建函数

![image-20240513233808527](https://img.0a0.moe/blog/2024/05/12/%E7%AC%AC%E4%B8%89%E5%B1%8A%E5%B9%BF%E4%B8%9C%E5%A4%A7%E5%AD%A6%E7%94%9F%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%94%BB%E9%98%B2%E7%AB%9E%E8%B5%9B-reversse/9b0f8855338ac679b5e9a049ca7251016b146815c5a77435f419a5fa0c38cb05.webp)

没看懂在干嘛，比赛时直接丢了

## re2

这个可以输入了。查看代码，首先是rand1部分。![image-20240513234013385](https://img.0a0.moe/blog/2024/05/12/%E7%AC%AC%E4%B8%89%E5%B1%8A%E5%B9%BF%E4%B8%9C%E5%A4%A7%E5%AD%A6%E7%94%9F%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%94%BB%E9%98%B2%E7%AB%9E%E8%B5%9B-reversse/dd1bb8651693d28c459474c29fe7175f9a7933417ee0bae2452d5618c0082ea6.webp)

通过查询`crc32_table`（未重命名前）的数据和对比代码，可以确定下方是一个标准的crc32算法。该部分输入5次，通过将输入向右位移处理后查表替换，然后存储到`v26`的位置，再对`v26`进行crc32计算。因此可以写出爆破脚本

```c
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

#define NUM_THREADS 16

unsigned int dword_B20EE0[256] = {
    // crc32table
};

typedef struct {
    int start;
    int end;
} ThreadArgs;

DWORD WINAPI search(LPVOID arg) {
    ThreadArgs* args = (ThreadArgs*)arg;

    uint32_t v8, v9, v10, v5;

    for(int i1 = args->start; i1 < args->end; i1++)
    {
        for (int i2 = 0; i2 < 256; i2++)
        {
            for (int i3 = 0; i3 < 256; i3++)
            {
                for (int i4 = 0; i4 < 256; i4++)
                {
                    for (int i5 = 0; i5 < 256; i5++)
                    {
                        uint8_t v26[5] = {i1, i2, i3, i4, i5};

                        v8 = dword_B20EE0[(unsigned char)(~((dword_B20EE0[(unsigned char)~(uint8_t)v26[0]])&0xff) ^ v26[1])] ^ ((dword_B20EE0[(unsigned char)~(uint8_t)v26[0]] ^ 0xFFFFFFu) >> 8);
                        v9 = dword_B20EE0[(unsigned char)(v8 ^ v26[2])] ^ (v8 >> 8);
                        v10 = dword_B20EE0[(unsigned char)(v9 ^ v26[3])] ^ (v9 >> 8);
                        v5 = ~(dword_B20EE0[(unsigned char)(v10 ^ v26[4])] ^ (v10 >> 8));

                        if (v5 == 0x27949C6C) {
                            printf("Found: %02x %02x %02x %02x %02x\n", i1, i2, i3, i4, i5);
                            // return 0;
                        }
                    }
                }
            }
        }
    }

    return 0;
}

int main(int argc, char const *argv[])
{
    HANDLE threads[NUM_THREADS];
    ThreadArgs threadArgs[NUM_THREADS];
    int step = 256 / NUM_THREADS;

    for (int i = 0; i < NUM_THREADS; i++) {
        threadArgs[i].start = i * step;
        threadArgs[i].end = (i + 1) * step;
        threads[i] = CreateThread(NULL, 0, search, (LPVOID)&threadArgs[i], 0, NULL);
    }

    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

    return 0;
}
```

经过一段时间等待跑出256个结果，然后可以通过反查位移推出可能的rand1的key

接下来是rand2部分![image-20240513234648747](https://img.0a0.moe/blog/2024/05/12/%E7%AC%AC%E4%B8%89%E5%B1%8A%E5%B9%BF%E4%B8%9C%E5%A4%A7%E5%AD%A6%E7%94%9F%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%94%BB%E9%98%B2%E7%AB%9E%E8%B5%9B-reversse/dc13f0142837fe55d8a7c5aceb4de8fa5e6639fc4a548d69c9f64bfd961661ba.webp)

该部分的下边依旧是一个crc32算法，对`byte_B24AD8`的16个字节进行crc32计算。上面部分是通过输入，对`byte_B24AD8`使用`v26`进行替换处理。第 i 个输入的数为 j，则`byte_B24AD8`的第 j 个数换成`v26`的第 i 个数。再次写出爆破脚本

```c
# include <stdio.h>
# include <stdint.h>
# include <stdlib.h>
# include <string.h>

unsigned int dword_B20EE0[256] = {
    // crc32table
};

unsigned char origin_byte_B24AD8[16] = {
    0x1B, 0xB1, 0xFF, 0xFD, 0x19, 0xFF, 0x89, 0x8C, 0x09, 0xFF, 0xFF, 0xD7, 0x4A, 0xB3, 0xFF, 0xEB
};

void swap(unsigned char* a, unsigned char* b) {
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

int count = 0;

void permute(unsigned char* arr, int start, int end, unsigned char result[120][5]) {
    if (start == end) {
        for (int i = 0; i <= end; i++) {
            result[count][i] = arr[i];
        }
        count++;
    } else {
        for (int i = start; i <= end; i++) {
            swap((arr+i), (arr+start));
            permute(arr, start+1, end, result);
            swap((arr+i), (arr+start)); // backtrack
        }
    }
}

void Combination(int arr[], int n, int r, int index, int data[], int i, unsigned char permute_result[120][5], unsigned char arr_origin[5]) {
    // 当组合大小与所需大小相同时，打印组合
    if (index == r) {
        // for (int j = 0; j < r; j++)
        //     printf("%d ", data[j]);
        // printf("\n");

        for (int k = 0; k < 120; k++){
            unsigned char byte_B24AD8[16];
            memcpy(byte_B24AD8, origin_byte_B24AD8, 16);
            for (int j = 0; j < r; j++){
                byte_B24AD8[data[j]] = permute_result[k][j];
            }
            uint32_t v16, v18, v19, v20;
            v16 = -1;
            for (int j = 0; j < 0x10; j += 4 )
            {
            v18 = dword_B20EE0[(unsigned char)(v16 ^ byte_B24AD8[j])] ^ (v16 >> 8);
            v19 = dword_B20EE0[(unsigned char)(v18 ^ byte_B24AD8[j+1])] ^ (v18 >> 8);
            v20 = dword_B20EE0[(unsigned char)(v19 ^ byte_B24AD8[j+2])] ^ (v19 >> 8);
            v16 = dword_B20EE0[(unsigned char)(v20 ^ byte_B24AD8[j+3])] ^ (v20 >> 8);
            }
            if ( ~v16 == 0x7F5E79B7 )
            {
                for (int j = 0; j < 16; j++)
                {
                    printf("%02x ", byte_B24AD8[j]);
                }
                printf("\n");
                for (int j = 0; j < 5; j++)
                {
                    printf("%02x ", arr_origin[j]);
                }
            }
        }
        return;
    }

    // 当没有更多的元素时返回
    if (i >= n)
        return;

    // 当前索引在组合中
    data[index] = arr[i];
    Combination(arr, n, r, index + 1, data, i + 1, permute_result, arr_origin);

    // 当前索引不在组合中
    Combination(arr, n, r, index, data, i + 1, permute_result, arr_origin);
}



int main(int argc, char const *argv[])
{
    FILE *file = fopen("rand1.txt", "r");
    if (file == NULL) {
        printf("Failed to open file\n");
        return 1;
    }

    char line[25];
    while (fgets(line, sizeof(line), file)) {
        int num1, num2, num3, num4, num5;
        sscanf(line, "Found: %x %x %x %x %x", &num1, &num2, &num3, &num4, &num5);
        
        unsigned char arr[] = {num1, num2, num3, num4, num5};
        unsigned char n = sizeof(arr)/sizeof(arr[0]);
        unsigned char result[120][5]; // 5! = 120
        count = 0;
        permute(arr, 0, n-1, result);

        int arr_index[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        int n1 = sizeof(arr_index)/sizeof(arr_index[0]);
        int data[5];

        Combination(arr_index, n1, 5, 0, data, 0, result, arr);
        
    }
    return 0;
}
```

得到处理后的`byte_B24AD8`为`1b b1 ed fd 19 ce 89 8c 09 f7 fc d7 4a b3 89 eb`，`v26`为`ed f7 fc 89 ce`，由此可以推断出rand2输入的值`2 9 10 14 5`，而rand1因为位移的原因存在多组可行解

```python
byte_B20DE0 = [0x57, 0x62, 0x35, 0xEF, 0x79, 0x3A, 0xC7, 0x9A, 0x8F, 0x2A, 0x13, 0x42, 0x51, 0xAF, 0x38, 0x4B, 0xC1, 0xB2, 0x3E, 0x09, 0x54, 0x2B, 0xAE, 0xE9, 0xE0, 0x7A, 0xDB, 0x55, 0x5C, 0x8C, 0xB7, 0xD2, 0xC6, 0x45, 0xB8, 0x1B, 0xB9, 0x22, 0xDF, 0x15, 0x23, 0x31, 0x68, 0x1F, 0xCA, 0x2F, 0x04, 0x76, 0x7F, 0x6B, 0x82, 0x60, 0xD5, 0x6D, 0xCE, 0x87, 0x4E, 0x21, 0x58, 0xF8, 0xCC, 0x9B, 0x0E, 0xA0, 0xDC, 0xC2, 0x26, 0x84, 0x24, 0xCF, 0xA4, 0xA6, 0xA9, 0xC5, 0xD3, 0x2C, 0x34, 0xA5, 0x0C, 0x5D, 0x02, 0x6A, 0xAA, 0x5A, 0xE2, 0x3C, 0xC3, 0x17, 0x7B, 0x19, 0xCB, 0xE6, 0xB4, 0x16, 0x43, 0x2E, 0x74, 0x08, 0x25, 0x99, 0x8B, 0xF9, 0x06, 0x8D, 0xFC, 0x5F, 0x86, 0x8A, 0x7C, 0xD9, 0x3D, 0xFE, 0xED, 0xEA, 0x61, 0x9F, 0xEB, 0xBE, 0xFA, 0xFD, 0xBB, 0x4F, 0xB6, 0x94, 0x29, 0xE1, 0x14, 0xAB, 0xD7, 0x89, 0x46, 0x92, 0x30, 0x0F, 0x41, 0xE4, 0x9E, 0x6C, 0xC0, 0xFB, 0xC9, 0xDD, 0xAD, 0x49, 0x03, 0xB3, 0x1E, 0x91, 0xDE, 0x90, 0xF4, 0x48, 0xD4, 0x4A, 0x6F, 0xE3, 0x64, 0x1D, 0xD8, 0xBF, 0xBA, 0xAC, 0x3F, 0xC4, 0x52, 0x20, 0x56, 0x12, 0x97, 0xEE, 0x2D, 0xBC, 0x07, 0xDA, 0xF5, 0x78, 0x85, 0x98, 0x0A, 0xCD, 0x0D, 0x6E, 0xA8, 0x28, 0x65, 0x5E, 0x88, 0xF1, 0x10, 0xE5, 0x9C, 0xA2, 0x47, 0x73, 0x0B, 0xF7, 0x75, 0xB0, 0x72, 0xC8, 0x39, 0x50, 0x7D, 0x80, 0x18, 0x70, 0x1A, 0xF6, 0x4C, 0x5B, 0xA3, 0xF0, 0xB5, 0x95, 0x59, 0xF2, 0x33, 0x66, 0x63, 0x9D, 0x69, 0xF3, 0x37, 0x77, 0x4D, 0x93, 0x53, 0x83, 0xD1, 0x71, 0x32, 0x05, 0x8E, 0x40, 0x1C, 0x36, 0x81, 0xB1, 0x96, 0xBD, 0x7E, 0x01, 0xD0, 0xD6, 0xE8, 0x44, 0xE7, 0x67, 0xA1, 0xEC, 0x3B, 0x27, 0x11, 0xA7, 0x00, 0x00]
v26 = [0xed, 0xf7, 0xfc, 0x89, 0xce]
move = [8, 16, 24, 0, 8]
origin = []
for i in v26:
    origin.append(byte_B20DE0.index(i))
for i in range(len(origin)):
    print(origin[i] << move[i])
# 28672 12779520 1744830464 129 13824
```

![image-20240513235554564](https://img.0a0.moe/blog/2024/05/12/%E7%AC%AC%E4%B8%89%E5%B1%8A%E5%B9%BF%E4%B8%9C%E5%A4%A7%E5%AD%A6%E7%94%9F%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%94%BB%E9%98%B2%E7%AB%9E%E8%B5%9B-reversse/5ba2a211fce2f2b50f83f50a2a38c822ec508d6d5e5b9937212ddaa25f064639.webp)

所以要怎么用key解密这个flag？

卡就卡在这里。看了别的wp才知道key是上面修改后的`byte_B24AD8`而不是输入的key😅

![image-20240514002655007](https://img.0a0.moe/blog/2024/05/12/%E7%AC%AC%E4%B8%89%E5%B1%8A%E5%B9%BF%E4%B8%9C%E5%A4%A7%E5%AD%A6%E7%94%9F%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%94%BB%E9%98%B2%E7%AB%9E%E8%B5%9B-reversse/527c5e5f2cd97cdedd45c078efad40570b8793ce33a5ba0d81420b9efc413cb6.webp)
