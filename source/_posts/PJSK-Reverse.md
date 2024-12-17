---
title: PJSK研究
comments: true
date: 2024-11-12 02:14:23
tags:
  - Unity
  - 动漫
  - 游戏
  - 逆向
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzbpbxp4zusuwja33zfkwhydvd6r
---


本文章仅供学习，严禁用于非法用途

## 环境准备

一台可以获取root能够运行frida的ARM架构手机，我这里为了避免影响老账号用了台二手的Pixel 6

这里踩过坑，当初想着模拟器x86能跑应该也能hook。但是实际上frida找不到经过libhoudini转译后的arm lib，找了一下也没找到有用的文章，避免麻烦就直接拿arm机器了。

刚拿到手时直接刷了15.0.0（AP3A.241105.007，2024 年 11 月），结果frida跑不起来，搜了下issue好像是跟谷歌8月的安全更新冲突了，无奈刷回7月A14的版本

## hook

然后就是参考文章在libil2cpp.so中找密钥解密global-metadata.dat，然后找Il2CppDumper恢复一下符号，用frida-il2cpp-bridge hook一下相关的class

```typescript
import "frida-il2cpp-bridge"

Il2Cpp.perform(() => {
    console.log(Il2Cpp.unityVersion);
    const game = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const Note = game.class("Sekai.Live.NoteBase");
    // console.log(Note);
    Il2Cpp.trace(true).classes(Note).and().attach();
});
```

看了下，LongNote的尾判是个NormalNote。



## 碎碎念

看到lib里面有检查frida和root的lib，不过开着frida进去也没见发生什么，大不了再开个号测试就是。检测是有些松，适合Unity游戏逆向入门

日服global-metadata.dat有一个简单的异或加密，通过搜索global-metadata.dat反查找可以找到一个函数，追踪进去可以找到异或的128bytes内容，然后对其异或解密即可用Il2CppDumper提取内容

国服内测看起来跟台服一样，直接删掉前8字节使用Il2CppDumper会报错，运行使用`ps -ef | grep [包名]`得pid，`cat /proc/[pid]/maps | grep global-metadata`得到内存地址，使用dd提取文件出来，再删掉前8字节即可使用Il2CppDumper不报错

## 参考文章

不确定文章作者愿不愿意链接被写，但为了尊重还是贴下

https://dev.moe/2157

https://mos9527.github.io/posts/pjsk/archive-20240105/

https://blog[.]mid[.]red/2023_09_30-58_B2_F1_D5-AF_1B_B1_FA

https://aza.moe/blog?post=2024-10-24-PJSK-Reversing

https://www.neko.ink/2023/10/15/dump-il2cpp-executable-from-memory/
