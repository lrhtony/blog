---
title: 给 Pixel6 构建 LineageOS 21.0
comments: true
date: 2025-12-15 16:57:09
tags:
  - 刷机
categories:
  - 技术
cover: https://img.0a0.moe/od/01tklsjzd77ggapwzelze2xybbi3zz5dlb 
---

> 封面：[Pixiv@わろじく](https://www.pixiv.net/artworks/119295833)

之前已经构建过一次了，但没有写blog记录，现在记录一下从头开始，给Pixel6 构建基于 Android14 的 LineageOS

## 准备

按照官方文档 https://wiki.lineageos.org/devices/oriole/build/ 进行操作，这里选择Ubuntu20.04进行操作，避免环境上的更多问题，反正就是 apt 安装环境然后配置，repo之类的可以配置一下镜像

## 拉取代码

把文档修改成要拉取的分支`lineage-21.0`，改成清华源

```bash
cd ~/android/lineage
repo init -u https://mirrors.tuna.tsinghua.edu.cn/git/lineageOS/LineageOS/android.git -b lineage-21.0 --git-lfs --no-clone-bundle
```

然后参考清华源的文档https://mirrors.tuna.tsinghua.edu.cn/help/lineageOS/修改 xml 文件

![mirrors](https://img.0a0.moe/od/01tklsjzfnohcfha6lprd2so3mpn2t2ec3)

然后同步代码

```bash
repo sync -j4
```

就可以漫长等待了

## 准备专有二进制

拉取完代码后，继续按照 LineageOS 文档操作

```bash
cd ~/android/lineage
source build/envsetup.sh
croot
breakfast oriole
```

这个步骤貌似没走镜像，建议开着代理。然后就会收到报错

![breakfast](https://img.0a0.moe/od/01tklsjzcsm2uk72v72vhy6z7xc6libgvu)

这时候你需要一台运行着 LineageOS 的手机，或者找 LineageOS 刷机包解出来。很遗憾的是，LineageOS 不对旧版本刷机包提供存档，只能找别人收集的 https://lineage-archive.timschumi.net/#oriole。我这里用的是`lineage-21.0-20241223-nightly-oriole-signed.zip`

没有`extract-files.py`，刷机包只有`payload.bin`，因此按照https://wiki.lineageos.org/extracting_blobs_from_zips_manually#extracting-files-from-payload-based-otas来提取

然后就会发现行不通，~~妈的怎么文档不一样了~~ https://github.com/LineageOS/lineage_wiki/commit/0c60a8a6bc6b9321185be6e54ffa0c815b32991e

反正就是挂载`system.img`到`system/`，然后尝试把剩下其他的 img 挂载到`system/`里面，能挂载的都挂载上，不能挂载就算了

然后到`~/android/lineage/device/google/oriole`下面运行

```bash
./extract-files.sh ~/android/system_dump/
```

然后包出问题的

![error1](https://img.0a0.moe/od/01tklsjzh5e7j6kt2byzaj4mfygwemyhn3)

解出来的包并没有`bootloader-*.img`的文件，搜索发现`abl.img`、`bl1.img`、`bl2.img`等已经是解出来的。查看`extract_files.sh`文件，可以发现里面调用了`prepare-firmware.sh`，里面调用 fbpacktool 解包 bootloader，因此可以直接把这行注释掉。文件路径如下

```
~/android/lineage/lineage/scripts/pixel/prepare-firmware.sh
```

![fix1](https://img.0a0.moe/od/01tklsjzbxyvwhoikm35fj6d5gzq2n3tin)

重新运行

```bash
./extract-files.sh ~/android/system_dump/
```

然后

```bash
croot
breakfast oriole
```

## 开始构建

按照文档

```bash
croot
brunch oriole
```

当然不会这么顺利

![error2](https://img.0a0.moe/od/01tklsjzbpivt25fkkqrfldkh4ecxuesp5)

发生了些冲突

在`~/android/lineage/device/google/raviole/oriole/proprietary-files-vendor.txt`里，可以看到发生了变更，这是前面`extract-files.sh`导致的

经过分析，可以通过在`~/android/lineage/device/google/raviole/oriole/skip-files-vendor.txt`添加上运行`extract-files.sh`要排除的文件

```
# Exclude specific files which may cause build errors
lib64/vendor.lineage.health-V1-ndk.so
lib64/vendor.lineage.powershare@1.0.so
lib64/vendor.lineage.touch@1.0.so
bin/erase_modemlog.sh
etc/vintf/manifest/vendor.lineage.health-service.default.xml
etc/vintf/manifest/vendor.lineage.powershare@1.0-service.pixel.xml
etc/vintf/manifest/vendor.lineage.touch@1.0-service.pixel.xml
bin/hw/vendor.lineage.health-service.default
bin/hw/vendor.lineage.powershare@1.0-service.pixel
bin/hw/vendor.lineage.touch@1.0-service.pixel
etc/init/vendor.lineage.health-service.default.rc
etc/init/vendor.lineage.powershare@1.0-service.pixel.rc
etc/init/vendor.lineage.touch@1.0-service.pixel.rc
etc/init/erase_modemlog.rc
etc/res/images/charger/percent_font.png
```

然后重新运行

```bash
./extract-files.sh ~/android/system_dump/
```

再重新运行

```bash
croot
brunch oriole
```

我配置 24G RAM + 24G SWAP，仍然有爆内存的情况

![OOM1](https://img.0a0.moe/od/01tklsjzaubrkrgdpvgfg3py3b4lphzjv3)

![OOM2](https://img.0a0.moe/od/01tklsjzguenjvm6xqpbazvzv2kh322ezf)

后面修改成 24 + 48 终于没爆了，推荐 64GB 内存编译

然后等就是了

最后构建出来的刷机包在`~/android/lineage/out/target/product/oriole`下面

## 测试

然后这一步应该清数据刷入真机测试一下的，懒得测了
