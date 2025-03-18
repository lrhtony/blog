---
title: 2025 长城杯铁人三项&CISCN 半决赛复盘
comments: true
date: 2025-03-19 00:40:24
tags:
  - CTF
categories:
  - 随笔
cover: https://img.0a0.moe/od/01tklsjzbtahamit4g2faklmk5wockwrxv
---

简单复盘一下比赛，随便写些东西

## AWDP

上年还是AWD今年就变成AWDP了，有好有坏，好处是不至于被其他队直接打穿上马疯狂拿分，坏处是像我逆向的就没得运维杀马蹭别人的马上车。打的时候web不会，只能看看pwn修复。给了10次机会，不用白不用，看着哪里感觉有问题patch一下丢上去check验证。刚好pwn的check exp判定不怎么严，能破坏掉exp的攻击链且不崩应该就算修复成功，然后就很凑巧的三道pwn的fix都过了🫠

patch的主要是free和snprintf。snprintf我看它参数不大对劲，直接把call的汇编nop掉就过了，如果check严一些的话这应该影响了程序功能的（）

这里贴个我认为还算标准的 [0psu3的Writeup](https://mp.weixin.qq.com/s?__biz=Mzk2NDQ0Mjk0Ng==&mid=2247483811&idx=1&sn=a7d2b965052f0546339a93db33303ce9)

结算截图

![image-20250319020636830](https://img.0a0.moe/od/01tklsjzbj4im7duc2gvfjvixhaikpcfoj)

## ISW

可能是下午脑子有点不清醒了。虽然一开始很顺利快速出了几个flag排到过全场第4/5的位置但后面就不行了，有图为证（）

![image-20250319011616748](https://img.0a0.moe/od/01tklsjzhovm34inmk65czuypnvq7v7fq5)

![image-20250319011549388](https://img.0a0.moe/od/01tklsjzfsfzjmyenyvfblcnpcvzhgaf7n)

然后隔壁暨大的Vp0int哐哐出取证的flag把我急坏了，中间还不小心压力的队友，如果有被伤害到实在是非常抱歉🙇‍♂️

翻看录像看这题的做题过程能看出头脑确实不清醒，人间都写明是dd镜像，明明是硬盘取证，我还拿内存取证工具去做。其次是能力确实不足，翻看过home目录下的`.viminfo`，没对里面的`/etc/systemd/system/system-upgrade.service`产生怀疑，还认为是Ubuntu自带的更新服务~~（看来如果我服务器被种马我可能也找不到）~~（不过确实伪装成系统服务还用`touch`修改文件时间真的很高明）。明明已经找到了下载痕迹`.system_upgrade`却还没对这串字符提起警惕。结束后向隔壁取经还可以看`/var/log/auth.log`，里面也能看到一些操作

```
Feb 24 12:53:18 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/mv rkt.tar.gz /
Feb 24 12:53:18 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 12:53:18 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 12:53:40 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/tar -xvf rkt.tar.gz
Feb 24 12:53:40 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 12:53:40 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 12:54:44 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/chmod +x /lib/systemd/systemd-agentd
Feb 24 12:54:44 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 12:54:44 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 12:56:50 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/touch /lib/systemd -r /lib/systemd/system
Feb 24 12:56:50 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 12:56:50 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:06:16 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/touch -t 202502241109.35 /lib/modules/5.4.0-84-generic/kernel/drivers/system
Feb 24 13:06:16 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:06:16 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:07:00 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/touch -t 202502241109.37776086595 /lib/modules/5.4.0-84-generic/kernel/drivers/system
Feb 24 13:07:00 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:07:00 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:07:08 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/touch -t 202502241109.37 /lib/modules/5.4.0-84-generic/kernel/drivers/system
Feb 24 13:07:08 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:07:08 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:08:14 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/systemctl reload
Feb 24 13:08:14 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:08:14 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:08:31 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/systemctl reload
Feb 24 13:08:31 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:08:31 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:09:35 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/systemctl reload system-upgrade.service
Feb 24 13:14:23 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/touch /etc/systemd/system/system-upgrade.service -r /etc/systemd/system/syslog.service
Feb 24 13:14:23 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:14:23 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:15:55 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/vim /etc/systemd/system/system-upgrade.service
Feb 24 13:15:55 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:16:01 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:16:07 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/sbin/reboot
Feb 24 13:18:34 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/vim /etc/systemd/system/system-upgrade.service
Feb 24 13:18:34 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:18:37 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:19:44 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/touch /etc/systemd/system/system-upgrade.service -r /lib/systemd/system/rsyslog.service
Feb 24 13:19:44 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:19:44 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:20:30 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/touch /etc/systemd/system/system-upgrade.service -r /etc/systemd/system/sshd.service
Feb 24 13:20:30 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:20:30 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:21:11 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/touch /etc/systemd/system/system-upgrade.service -r /etc/systemd/system/timers.target.wants/apt-daily.timer
Feb 24 13:21:11 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:21:11 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:21:38 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/touch /etc/systemd/system/system-upgrade.service -r /etc/systemd/system/open-vm-tools.service.requires/vgauth.service
Feb 24 13:21:38 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:21:38 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:21:47 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/touch /etc/systemd/system/system-upgrade.service -r /etc/systemd/system/open-vm-tools.service.requires/
Feb 24 13:21:47 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:21:47 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:22:54 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/touch -t 201804210055.56 /etc/systemd/system
Feb 24 13:22:54 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:22:54 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:23:42 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/chmod 777 /etc/systemd/system/system-upgrade.service
Feb 24 13:23:42 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:23:42 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:24:01 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/chmod 755 /etc/systemd/system/system-upgrade.service
Feb 24 13:24:01 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:24:01 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:24:34 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/rm /rkt.tar.gz
Feb 24 13:24:34 localhost sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Feb 24 13:24:34 localhost sudo: pam_unix(sudo:session): session closed for user root
Feb 24 13:26:49 localhost sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/sbin/poweroff
```

然后systemd里面

```
[Unit]
Description=system-upgrade
After=multi-user.target
[Service]
Type=forking
ExecStart=/sbin/insmod /lib/modules/5.4.0-84-generic/kernel/drivers/system/system-upgrade.ko
[Install]
WantedBy=multi-user.target
```

把内核文件提取出来逆向即可，这个是文件维持连接器的

![image-20250319013552428](https://img.0a0.moe/od/01tklsjzctec2p2mrpmncl3fxqwdwf257y)

连接器是`/lib/systemd/systemd-agentd`，在这里逆向和上面chmod都可以看到

然后后面要反击的话应该要搭个frp去打57.207和57.203，这些都是后话了

总之能力相比大佬确实还有些不足，只能说继续提升吧😭题目还是挺好玩的