---
title: Frida绕过梆*加固检测后kill
comments: true
date: 2025-08-24 02:27:01
tags:
  - 逆向
categories:
  - 技术
---



在分析某款APP的时候发现用了梆*加固企业版，开着frida进去会被kill。尽管用的是Florida patch过的，也自己去了会inline hook libc的abort和exit的地方，但开着进去还是会被检测到然后被kill掉app进程（虽说frida特征挺多的，server一开就改各种权限hook各种东西，被检测到也挺正常）

可以观察到app是被kill掉的而不是有一些应用是造crash崩溃退出，因此可以使用stackplz对kill的syscall进行hook，打印堆栈快速定位到kill的位置，然后hook对应的函数直接返回即可绕过。（不过这样还是没有解决被检测到的问题，想要不被检测还是不要用frida吧w