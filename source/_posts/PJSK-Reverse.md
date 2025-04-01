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

刚拿到手时直接刷了15.0.0（AP3A.241105.007，2024 年 11 月），结果frida跑不起来，搜了下issue好像是跟谷歌8月的安全更新冲突了，无奈刷回7月A14的版本。现在修了又可以了。

## hook

然后就是参考文章在libil2cpp.so中找密钥解密global-metadata.dat，然后找Il2CppDumper恢复一下符号，用frida-il2cpp-bridge hook一下相关的class，先用trace查看调用细节，再用`implementation`覆盖函数查看入参和返回

通过IDA查看音游判定部分的逻辑，看了一下貌似没有做很严的反作弊，直接改判定结果就行了。比较相关的参数是`NoteState`和`JudgeInfo`，`JudgeInfo`包含`NoteResult`和`NoteResultDescription`两部分，使用`System.ValueTuple`进行组合，IDA中查找相应的泛型实例化的引用，就可以快速的找到不同Note判定的函数，再对应进行修改即可。同时可以发现每个Note在Miss前State会变成Last，判定信息设定为Miss后再变为Done结束一个Note的生命周期，针对这点就可以方便地进行hook。
然后测试多人Live打了1局就Ban了，单人测试了几次没Ban，应该抓包看看，估计有上传别的数据，可能是Touch数据，也可能是别的统计。因为hook了Last状态，而正常变成Last状态后结果应该是Miss，如果有别的函数统计了Last状态，只要比对Last和Miss能否对上就能判定作弊。如果是检验Touch就难搞，需要构建Touch对象，里面挺复杂的还有几个Vector。避免变为Last只能在时间还没到超出判定时间调用Done。尝试过hook`get_Progress`函数，Progress==1即判定位置，但由于每个frame都会调用该函数，note多的时候会导致整体卡顿，效果不大好。总之应该先抓包看看会上传什么数据，再进一步去绕过。

> 现在想起来好像有个点击时的偏移好像没改（

本地针对root和frida检测的lib都hook了也没看到调用。

## 碎碎念

看到lib里面有检查frida和root的lib，不过开着frida进去也没见发生什么，大不了再开个号测试就是。检测是有些松，适合Unity游戏逆向入门

日服global-metadata.dat有一个简单的异或加密，通过搜索global-metadata.dat反查找可以找到一个函数，追踪进去可以找到异或的128bytes内容，然后对其异或解密即可用Il2CppDumper提取内容

国服内测看起来跟台服一样，直接删掉前8字节使用Il2CppDumper会报错，运行使用`ps -ef | grep [包名]`得pid，`cat /proc/[pid]/maps | grep global-metadata`得到内存地址，使用dd提取文件出来，再删掉前8字节即可使用Il2CppDumper不报错

## 参考文章

https://dev.moe/2157

https://mos9527.github.io/posts/pjsk/archive-20240105/

https://blog.mid.red/2023_09_30-58_B2_F1_D5-AF_1B_B1_FA

https://aza.moe/blog?post=2024-10-24-PJSK-Reversing

https://www.neko.ink/2023/10/15/dump-il2cpp-executable-from-memory/
