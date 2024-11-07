---
title: 使用IDA对Android so进行动调
comments: true
date: 2024-07-08 15:56:01
tags:
  - CTF
categories:
  - 技术
---

最近学了下Frida框架，跟着[Frida-Labs](https://github.com/DERE-ad2001/Frida-Labs)这个项目来学效果还不错。我也是借着这个项目学一下在IDA里动调so。本篇博客主要也是记录下动调的过程与一些坑

## 环境准备

需要一台拥有Root权限的手机/模拟器，这里可以使用实体机解bl锁后获取Root权限，但为了防止逆向过程中把手机搞崩还是建议使用非主力机或模拟器。我这里使用Android Studio里自带的AVD，搭配[rootAVD](https://gitlab.com/newbit/rootAVD)刷入Magisk框架，过程参考了https://www.bilibili.com/read/cv25705003

然后这里用的是`Frida 0x8`这道题，使用adb安装，然后push IDA的sevrer到`/data/local/tmp`，使用`su`权限运行即可。

## 开始调试

运行后转发IDA server端口到本机

```bash
adb forward tcp:23946 tcp:23946
```

将APK文件解包，将运行的对应架构so文件拖入对应版本IDA，这里我用是是`x86_64`架构。然后在对应函数下断点，我这里是`cmpstr`

![image-20240712232247988](https://img.0a0.moe/od/01tklsjzbrqnnq7pi5tbb2w5ibx762qdx3)

配置Remote Linux debugger的Hostname和Port

![image-20240712232346619](https://img.0a0.moe/od/01tklsjzgoiagugjn34za2zuhzj6vooneb)

调试模式启动应用

```bash
adb shell am start -D -n com.ad2001.frida0x8/.MainActivity
```

因为这个应用的属性`android:debuggable="true"`，因此可以直接调试。否则可能需要改包或者

```bash
adb shell
su
magisk resetprop ro.debuggable 1
stop;start; 
```

然后找到PID，我这里使用`frida-ps -U`，其他方法同理。然后使用顺手的端口号转发

```bash
adb forward tcp:[port] jdwp:[pid]
```

IDA-Debugger-Attach to process...，里面找到进程，可以<kbd>Ctrl</kbd>+<kbd>F</kbd>查找，这里也能看到pid![image-20240712233456572](https://img.0a0.moe/od/01tklsjzds434vj2itv5fzsa6u7ermp3xn)

然后使用`jdb`连接就行了

```bash
jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=[port]
```

推荐在IDA的Debugger setup里把`Suspend on process entry point`、`Suspend on thread start/exit`、`Suspend on library load/unload`勾上。然后就能正常调试了。

我们可以看到`Output`窗口看到引入的so文件和进程的开始结束。在汇编区<kbd>Ctrl</kbd>+<kbd>S</kbd>可以看到引入的so文件和位置。

## 坑

如果我们现在直接运行的话，是找不到引入的`libfrida0x8.so`文件的，断点也无法生效，搜索得知是`android:extractNativeLibs="false"`这个属性导致的问题。这个属性会导致应用安装时不释放lib文件到安装文件夹，运行时只会从`base.apk`中读取，定位不到对应的so文件。解决办法有二：一是解包修改属性后重打包；二是导出对应架构的so文件，找到对应的安装文件夹

```bash
adb shell pm path com.ad2001.frida0x8
```

然后将lib文件复制进去`/data/app/~~m3jiydVaec6iWb_wo2-VIg==/com.ad2001.frida0x8-n-XnSCp7x4hizYDHlvdh0w==/lib/x86_64`

这时应用运行时优先使用lib中的so文件

![image-20240712235323035](https://img.0a0.moe/od/01tklsjzggsdm65n26p5gz7od7pgjvf236)

## 继续调试

这时就能在断点处正常断下了![image-20240712235529299](https://img.0a0.moe/od/01tklsjzeyjcftnsrrrvbifq2jkbqq3rrx)

平时怎么动调现在怎么动调就行，对应的变量的值也能够正常读取显示

![image-20240712235713830](https://img.0a0.moe/od/01tklsjzbu6tuf47mxavck7kjfxp626cwu)

至此通过IDA完成对Android so文件的动调
