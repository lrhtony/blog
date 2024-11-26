---
title: 2024 鹏城杯 Reverse Writeup
comments: true
date: 2024-11-09 19:34:39
tags:
  - CTF
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzh6fosue5iz7rfjtukox3yeodxq
---

封面：[X@ningen_mame](https://x.com/ningen_mame/status/1855187323832750153)
难的题还是不会做

## exec

这道题出的有问题，解出来的答案是无法验证的。其实严格来说也不能算解出来，只能说蒙对。

注意到脚本循环嵌套exec、base解密，因此可以直接用脚本替换跑出最终结果

```python
import base64
t=(...).decode()

while 'base64' in t:
    t = t.replace('exec', 't=')
    exec(t)
    t = t.decode()

with open('chall2.py', 'w') as f:
    f.write(t)
```

然后得到有问题的脚本

```python
a=True
d=len
G=list
g=range
s=next
R=bytes
o=input
Y=print
def l(S):
 i=0
 j=0
 while a:
  i=(i+1)%256
  j=(j+S[i])%256
  S[i],S[j]=S[j],S[i]
  K=S[(S[i]+S[j])%256]
  yield K
def N(key,O):
 I=d(key)
 S=G(g(256))
 j=0
 for i in g(256):
  j=(j+S[i]+key[i%I])%256
  S[i],S[j]=S[j],S[i]
 z=l(S)
 n=[]
 for k in O:
  n.append(k^s(z)+2)
 return R(n)
def E(s,parts_num):
 Q=d(s.decode())
 S=Q//parts_num
 u=Q%parts_num
 W=[]
 j=0
 for i in g(parts_num):
  T=j+S
  if u>0:
   T+=1
   u-=1
  W.append(s[j:T])
  j=T
 return W
if __name__=='__main__':
 L=o('input the flag: >>> ').encode()
 assert d(L)%2==0,'flag length should be even'
 t=b'v3ry_s3cr3t_p@ssw0rd'
 O=E(L,2)
 U=[]
 for i in O:
  U.append(N(t,i).hex())
 if U==['1796972c348bc4fe7a1930b833ff10a80ab281627731ab705dacacfef2e2804d74ab6bc19f60',2ea999141a8cc9e47975269340c177c726a8aa732953a66a6af183bcd9cec8464a']:
  Y('Congratulations! You got the flag!')
 else:
  Y('Wrong flag!')
```

出题人本意是让做题人利用RC4异或的性质，将密文送入加密函数即可得到结果，然后又想魔改RC4，结果改出问题，所以我们把数据送入函数即可

```python
t = b'v3ry_s3cr3t_p@ssw0rd'
U = ['1796972c348bc4fe7a1930b833ff10a80ab281627731ab705dacacfef2e2804d74ab6bc19f60','2ea999141a8cc9e47975269340c177c726a8aa732953a66a6af183bcd9cec8464a']
for i in U:
    print(N(t, bytes.fromhex(i)).decode(),end='')
# flag{thEn_I_Ca5_BE_YoUR_Onl7_ExeCUti6n_So_Use_m3_t0_R0n_tH17_Ex3Cuti0n}
```

## joyVBS

```vbscript
MsgBox "VBScript, often abbreviated as VBS, is an event-driven programming language developed by Microsoft, primarily used for scripting in the Windows environment."
MsgBox "It is based on the Visual Basic programming language and is designed to be simple and easy to use, especially for those familiar with the BASIC programming language."
MsgBox "And for me, it is the first programming language that I've leart"
MsgBox "Hackers! Have fun with this VBS challenge!"
flag = InputBox("Enter the FLAG:", "Hack for fun")
wefbuwiue = "NalvN3hKExBtALBtInPtNHTnKJ80L3JtqxTboRA/MbF3LnT0L2zHL2SlqnPtJLAnFbIlL2SnFT8lpzFzA2JHrRTiNmT9"

qwfe = 9+2+2+1

Function Base64Decode(base64EncodedString)
    Dim xml, elem
    Set xml = CreateObject("MSXML2.DOMDocument")
    Set elem = xml.createElement("tmp")
    elem.dataType = "bin.base64"
    elem.text = base64EncodedString
    Dim stream
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1 'Binary
    stream.Open
    stream.Write elem.nodeTypedValue
    stream.Position = 0
    stream.Type = 2 'Text
    stream.Charset = "utf-8"
    Base64Decode = stream.ReadText
    stream.Close
End Function
Function Caesar(str,offset)
        Dim length,char,i
        Caesar = ""
        length = Len(str)
        For i = 1 To length
                char = Mid(str,i,1)
                If char >= "A" And char <= "Z" Then
                        char = Asc("A") + (Asc(char) - Asc("A") + offset) Mod 26
                        Caesar = Caesar & Chr(char)
                ElseIf char >= "a" And char <= "z" Then
                        char = Asc("a") + (Asc(char) - Asc("a") + offset) Mod 26
                        Caesar = Caesar & Chr(char)
                Else
                        Caesar = Caesar & char
                End If
        Next
End Function

If flag = Base64Decode(Caesar(wefbuwiue, 26-qwfe)) Then
    MsgBox "Congratulations! Correct  FLAG!"
Else
    MsgBox "Wrong flag."
End If
```

明文比对，直接在比对上面用WScript.Echo输出就得到flag了

## Re5

Tea加密，然后通过SEH修改栈的数据。通过触发除0错误来srand(0)，通过xor eax, eax;mov [eax], eax触发不可访问内存来触发rand()。程序结合以上内容和简单的TEA实现对flag的加密

因此可以先生成随机数4x(0x20)个随机数

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    srand(0);
    for (int i = 0; i < 4*0x20; i++)
    {
        printf("0x%x,", rand());
    }
    return 0;
}
```

然后对Tea加密的脚本修改一下就行

```python
encrypted = [0xEA2063F8, 0x8F66F252, 0x902A72EF, 0x411FDA74, 0x19590D4D, 0xCAE74317, 0x63870F3F, 0xD753AE61]
deltas = [0x26, 0x1e27, 0x52f6, 0x985, 0x2297, 0x2e15, 0x20ad, 0x7e1d, 0x28d2, 0x7794, 0x16dd, 0x6dc4, 0x476, 0x119, 0x5039, 0x3e31, 0x22f1, 0x66ad, 0xbb5, 0x3958, 0x51f0, 0x7c93, 0x5497, 0x6532, 0x4819, 0x52b, 0x70d1, 0x8c0, 0x25fd, 0x7e16, 0x98e, 0x24e, 0x348, 0x489b, 0x420b, 0x52f5, 0x5c3b, 0x3149, 0x30a8, 0x363, 0x735d, 0x1ade, 0x6e3f, 0x45df, 0x7b6d, 0x5068, 0x2fb4, 0x7987, 0x1d9a, 0x42aa, 0x1dcd, 0x72dc, 0x2ff7, 0x34c1, 0x5f44, 0x2d81, 0x3029, 0x1c08, 0x91b, 0x4b40, 0x5662, 0x3738, 0x6930, 0x44e, 0x5494, 0x20d4, 0x5f11, 0x6cd0, 0x15de, 0x60c4, 0x3711, 0x339d, 0x124b, 0x413f, 0x3b9c, 0x3e46, 0xabb, 0x6aef, 0x70c7, 0x4654, 0x4121, 0xc50, 0x2e2b, 0x5bd0, 0xef, 0x105a, 0xaf4, 0x7109, 0xbcf, 0x285f, 0x5035, 0x5391, 0x3e94, 0x2d36, 0x657f, 0x3689, 0x270, 0x1b99, 0x6bb1, 0x321e, 0x5e67, 0x2fcc, 0x7a11, 0x5c54, 0x3d03, 0x647f, 0x319c, 0x5f03, 0x3a4a, 0x58f6, 0x1a9b, 0x2f1e, 0xded, 0x6267, 0x77, 0x493b, 0x65c2, 0x4ca4, 0x3fce, 0x1750, 0x4474, 0xdf9, 0x3ac6, 0x63bb, 0x387a, 0x7258, 0x67a2, 0x7d86]

def tea_decrypt(ciphertext, key, index):
    delta = deltas[index * 32: index * 32 + 32]
    v0 = ciphertext[0] & 0xffffffff
    v1 = ciphertext[1] & 0xffffffff
    sum = 0

    for i in range(32):
        sum = (sum + delta[i]) & 0xffffffff

    for i in range(32):
        v1 = (v1 - ((key[0] + (v0 >> 5)) ^ (sum + v0) ^ (key[1] + 16 * v0))) & 0xffffffff
        v0 = (v0 - ((key[2] + (v1 >> 5)) ^ (sum + v1) ^ (key[3] + 16 * v1))) & 0xffffffff
        sum = (sum - delta[31 - i]) & 0xffffffff

    return v0, v1

def int_to_bytes(n):
    return chr(n & 0xff) + chr((n >> 8) & 0xff) + chr((n >> 16) & 0xff) + chr((n >> 24) & 0xff)

for i in range(4):
    cipher = [encrypted[i * 2], encrypted[i * 2 + 1]]
    key = [3, 3, 2, 2]
    decrypted = tea_decrypt(cipher, key, i)
    print(int_to_bytes(decrypted[0]) + int_to_bytes(decrypted[1]), end='')
# d555ce75ec293c8ed232d83dffb0ff82
```

## Rafflesia

main函数有花指令patch掉即可。

尝试动调发现有反调试弹窗阻止动调，找到在函数TlsCallback_0中，此处下个断点，在IDA运行到此处时手动控制运行eip运行方向

在memcmp处下断点，此时我们可以dump处上面encode时的base64码表HElRNYGmBOMWnbDvUCgcpu1QdPqJIS+iTry39KXse4jLh/x26Ff5Z7Vokt8wzAa0

base64后有个异或

![img](https://img.0a0.moe/od/01tklsjzczjlsggbtvznajjl6u6vav5ujj)

![img](https://img.0a0.moe/od/01tklsjzc5luwuabvnn5fjbggnsdvrjl6t)