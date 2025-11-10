---
title: 支付宝神秘Pyc
comments: true
date: 2025-11-03 00:39:58
tags:
  - 逆向
  - 风控
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjze5t7ilok5jpza2r75nyxhzmcz4
---

发现自己研究用的Pixel 6的支付宝Android文件目录下有一些神秘pyc文件还有xnn模型，明文可以看到有些点击检测的文字以及一些内网地址，遂全部提取。发现用的是Python2.7，使用uncompyle6就能全部反编译。文件编译的日期跨度挺大，2022年到2025.10的都有。

用的好像是内部的maipython库，里面有一些信息收集上报还有设备风控姿态识别的代码。xnn模型好像是内部代码库所以也测试不了

![image-20251110225358105](https://img.0a0.moe/od/01tklsjzgo2zotba6qojflwryn3csvtsuh)

