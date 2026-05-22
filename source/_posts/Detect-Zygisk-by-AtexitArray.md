---
title: 通过 AtexitArray 检测 Zygisk
comments: true
date: 2025-12-12 16:42:24
tags:
  - 风控
categories:
  - 技术
---

> 封面：[Pixiv@ホシノナナ（くん）](https://www.pixiv.net/artworks/137424424)

起因是发现 [Native Detector](https://github.com/reveny/Android-Native-Root-Detector) 可以检测 Zygisk，然后看到了 5ec1cff 的这个修复 https://github.com/5ec1cff/local_cxa_atexit_finalize_impl

终于有空就验证了一下

## 验证

将 libc.so 提取出来，查看`g_array`的偏移。可以看到app运行时用到的 libc 是`/apex/com.android.runtime/lib/bionic/libc.so`，提取出来丢 IDA 分析，找到`_cxa_atexit`函数，找到 g_array，即可看到`g_array`的偏移

![garray_偏移](https://img.0a0.moe/blog/2025/12/12/%E9%80%9A%E8%BF%87-atexitarray-%E6%A3%80%E6%B5%8B-zygisk/9c56957a2207a83b00dc8ab9ce32e31fc5982182f0ed3ce183de8f32b0e4119b.webp)

这里对应的应该是 atexit.cpp 源码里 class AtexitArray 的私有变量，结合源码丢 AI 分析可猜测含义

![g_array_fields](https://img.0a0.moe/blog/2025/12/12/%E9%80%9A%E8%BF%87-atexitarray-%E6%A3%80%E6%B5%8B-zygisk/f2534ef37caf3502558253da480597bf63b3ccf00d212a2de75f10648c332735.webp)

先不考虑兼容性，使用固定偏移测试，读取上面的几个 field，即可发现一些端倪。在开启一些未经过修复的 Zygisk 模块的时候，`extracted_count_`不为 0

![image-20260522210034893](https://img.0a0.moe/blog/2025/12/12/%E9%80%9A%E8%BF%87-atexitarray-%E6%A3%80%E6%B5%8B-zygisk/90d158c88186653c0567c8d1a864d3c467bd93274ea33e683dbda95113808520.webp)

再进一步对`array_`的指针进行解析，可以发现存在为 0 的 gaps

![image-20260522210044755](https://img.0a0.moe/blog/2025/12/12/%E9%80%9A%E8%BF%87-atexitarray-%E6%A3%80%E6%B5%8B-zygisk/26ec5ab4bbbd0d000390c19256af4b4fa6970386e212e08978bf2f097ed1253a.webp)

因此我们可以写出对应的检测

## 完善

前面我们为了方便，是直接写死偏移的，但是不同设备的 libc 对应的偏移都不同。我拉了几个设备的 libc 下来看，发现基本上都有`_ZL7g_array`或`_ZL7g_array.0`的符号，没有被 strip 掉。因此可以直接解析对应 libc 的 elf，找到对应符号的地址偏移，加上 base 就可以了

![another_symbol](https://img.0a0.moe/blog/2025/12/12/%E9%80%9A%E8%BF%87-atexitarray-%E6%A3%80%E6%B5%8B-zygisk/1190612ea1a0e9938001ce863a775ec0a85fbb011a20f7c9f9489e968908263b.webp)

## 测试

跑路了没有公司的云测平台，只能用 Android Studio 自带的 firebase 简单测了一下。基本上没什么大问题，正常机器基本都是 0，除了 OPPO

![OPPO1](https://img.0a0.moe/blog/2025/12/12/%E9%80%9A%E8%BF%87-atexitarray-%E6%A3%80%E6%B5%8B-zygisk/0c1bd5902bedbc8dddf65e51c196c33d1072ce55eab0be9456eea753d39b91fd.webp)

![OPPO2](https://img.0a0.moe/blog/2025/12/12/%E9%80%9A%E8%BF%87-atexitarray-%E6%A3%80%E6%B5%8B-zygisk/eb5a6b10ad18ca2fb087aa41b26ca1bc3c16e0216a12c57e7f9e911c3471b5f9.webp)

不过这个可能是系统自带的，相比 Zygisk 造成的大量 gaps 一两个貌似不能说明什么。安装 Native Detector 也没有误报，应该是有一个阈值。

目前代码兼容性感觉还不怎么好也测试不了，因此就先不贴了，有空再放出来吧。

第一次研究这方面内容如果有哪方面错了也欢迎各位大佬指正。
