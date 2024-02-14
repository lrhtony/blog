---
title: AI在逆向中的应用
comments: true
date: 2024-01-28 17:58:15
tags:
  - CTF
categories:
  - 技术
---
在做题中，AI可以在一些加密算法中起到作用

像练习里的normal1

```c
void __fastcall sub_A84(char a1[], _BYTE *a2)
{
  char v3; // [rsp+19h] [rbp-7h]
  unsigned __int8 v4; // [rsp+1Ah] [rbp-6h]
  unsigned __int8 i; // [rsp+1Bh] [rbp-5h]
  int v6; // [rsp+1Ch] [rbp-4h]

  v3 = 0;
  v4 = 0;
  v6 = 0;
  while ( a1[v6] )
  {
    *a2++ = table((unsigned __int8)(((int)(unsigned __int8)a1[v6] >> (v4 + 2)) | v3));
    v4 = (v4 + 2) & 7;
    v3 = 0;
    for ( i = 0; i < v4; ++i )
      v3 |= ((1 << i) & (unsigned __int8)a1[v6]) << (6 - v4);
    if ( v4 <= 5u )
      ++v6;
  }
  *a2 = 0;
}
```

我没能看出来这是Base64，但我使用Bing就能提示出来

<img src="https://img.jks.moe/od/01tklsjzbmuya3iepptffzpdqiuovx4agw" style="zoom:50%;" />

<img src="https://img.jks.moe/od/01tklsjzcgritrfebxzfh3q3umprey5sfe" style="zoom:50%;" />

以及像AES算法

<img src="https://img.jks.moe/od/01tklsjzcuy42s5gzmdvei57k6mywolveq" style="zoom:50%;" />

还有像normal21中的RC4算法

```c
void __cdecl sub_401850(_DWORD *a1, int a2, int a3)
{
  int v3; // eax
  _DWORD *v4; // edi
  int *v5; // ebx
  int v6; // ecx
  int v7; // eax
  int v8; // esi
  char v9; // dl
  int *v10; // edx

  v3 = 0;
  v4 = a1 + 2;
  *a1 = 0;
  a1[1] = 0;
  do
  {
    v4[v3] = v3;
    ++v3;
  }
  while ( v3 != 256 );
  v5 = a1 + 2;
  v6 = 0;
  LOBYTE(v7) = 0;
  do
  {
    v8 = *v5;
    v9 = *(_BYTE *)(a2 + v6++) + *v5;
    v7 = (unsigned __int8)(v9 + v7);
    v10 = &v4[v7];
    *v5 = *v10;
    *v10 = v8;
    if ( v6 >= a3 )
      v6 = 0;
    ++v5;
  }
  while ( v5 != a1 + 258 );
}
```

<img src="https://img.jks.moe/od/01tklsjzea6v5o6wdxt5bklmjzgm7e2x2a" style="zoom:50%;" />

```c
void __cdecl sub_4018D0(_DWORD *a1, _BYTE *a2, int a3)
{
  int v3; // edx
  int v4; // ecx
  _DWORD *v5; // esi
  _BYTE *v6; // ebx
  int v7; // edi
  int *v8; // eax
  int v9; // edx
  int v10; // ebp
  int *v11; // [esp+0h] [ebp-18h]

  v3 = *a1;
  v4 = a1[1];
  v5 = a1 + 2;
  if ( a3 > 0 )
  {
    v6 = a2;
    v7 = *a1;
    do
    {
      v7 = (unsigned __int8)(v7 + 1);
      v8 = &v5[v7];
      v9 = *v8;
      v4 = (unsigned __int8)(*v8 + v4);
      v11 = &v5[v4];
      v10 = *v11;
      *v8 = *v11;
      *v11 = v9;
      *v6++ ^= v5[(unsigned __int8)(v9 + v10)];
    }
    while ( v6 != &a2[a3] );
    v3 = v7;
  }
  *a1 = v3;
  a1[1] = v4;
}
```

<img src="https://img.jks.moe/od/01tklsjzhy6333mrzppzhj4zbsqzj4xgjw" style="zoom:50%;" />

但是要注意AI的能力有限，对于一些修改AI可能识别不出来，像安洵杯这个魔改的base64

```c
__int64 __fastcall sub_140001360(char a1[], char a2[], int a3)
{
  int v4; // [rsp+0h] [rbp-88h]
  int v5; // [rsp+4h] [rbp-84h]
  char v6[80]; // [rsp+10h] [rbp-78h] BYREF

  strcpy(v6, "4KBbSzwWClkZ2gsr1qA+Qu0FtxOm6/iVcJHPY9GNp7EaRoDf8UvIjnL5MydTX3eh");
  v4 = 0;
  v5 = 0;
  while ( v4 < a3 )
  {
    a1[v5] = v6[a2[v4] & 0x3F];
    a1[v5 + 1] = v6[(4 * (a2[v4 + 1] & 0xF)) | ((a2[v4] & 0xC0) >> 6)];
    a1[v5 + 2] = v6[(16 * (a2[v4 + 2] & 3)) | ((a2[v4 + 1] & 0xF0) >> 4)];
    a1[v5 + 3] = v6[(a2[v4 + 2] & 0xFC) >> 2];
    v4 += 3;
    v5 += 4;
  }
  if ( a3 % 3 == 1 )
  {
    a1[v5 - 2] = '=';
    a1[v5 - 1] = '=';
  }
  else if ( a3 % 3 == 2 )
  {
    a1[v5 - 1] = '=';
  }
  return 0i64;
}
```

<img src="https://img.jks.moe/od/01tklsjzgprueprbezyzg3xfgx6uot7flu" style="zoom:50%;" />
