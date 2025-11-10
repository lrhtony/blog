---
title: QQ设备id引出的一些小分析
comments: true
date: 2025-11-10 23:18:58
tags:
  - 风控
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjze2eby6aqo3vjejorv7pcsss4h4
---

最近在清老手机小米10上的设备ID。想着现在Android14外部存储权限管理严格，把能看到的可能是设备id的文件和目录全部清掉，防止设备被标记（清完后我的美团半黑号确实解了）。然后就发现了在/sdcard/Android下面，每次打开QQ都会生成一个`.android_lq`的设备id文件。

当初还以为是有什么神秘漏洞可以路径穿越写Android目录，因为发现给了图片音频的存储权限后才能写，不给就写不了，正常来说给了这个存储权限也是写不了Android目录的。

然后又仔细分析了下，发现了应用安装时间2021年。由于是MIUI11还是12升上来的，那时候的存储管理做得并没有那么细，应用拿存储权限可以直接获得外部全局存储，然后就可以到处拉屎了。然后Android版本升上来后，虽然存储权限进一步加强了限制，但为了保证应用的兼容性，Android系统还是保留了`requestLegacyExternalStorage`和`preserveLegacyExternalStorage`，让在Manifest中声明了这两项的应用在Android版本升级后获取外部存储权限时依然能获取传统的全局存储，导致全局可读可写。

因此解决办法就是将应用卸载后重装，确实文件没有再次出现过。

我确实没有想到升级过几个Android大版本后像QQ这些软件仍然能获取到`LegacyExternalStorage`，又看了下QQ音乐的目录修改时间和QQ音乐的安装时间，也是有外部存储权限，如法炮制。

现在的App想拉屎，由于Android限制，只能在Download、Pictures下面拉。考虑到跨应用读取以及未来存储权限收紧，可以使用文件路径存储设备id，读取时只需判断路径是否存在，判断存在并不需要存储权限。目前文件路径存储设备id见到过两个方案：

1. utdid通过01路径将字节转化为二进制存储；
2. 不知道哪家将hex拆成两半，每字节最多判断2x16次是否存在。
