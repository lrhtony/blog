---
title: 编译带有 JA4 指纹的 OpenResty
comments: true
date: 2026-01-27 12:00:06
tags:
  - OpenResty
  - 风控
  - 设备指纹
categories:
  - 技术
---

想用 OpenResty 收集 JA4 指纹信息，以便后续进一步处理。找了一圈没找到文章代码仓库之类的，遂写篇文章记录下。

 由于各方面仍在进一步开发中，文章受限于版本问题，只对我写这篇博客的时候有效，若更新需要进一步验证

## 修改编译

OpenResty 我用的是我这时候的最新版本 1.27.1.2。OpenResty 基于 Nginx 修改而来，版本号前面对应的就是 Nginx 的版本号。在 JA4 的[官方仓库](https://github.com/FoxIO-LLC/ja4)里，可以找到官方对 Nginx 的支持模块，我写这篇文章的时候对应的仓库及版本 [FoxIO-LLC / ja4-nginx-module](https://github.com/FoxIO-LLC/ja4-nginx-module/commit/8d210cb).

由于 OpenResty 和 ja4-nginx-module 都对 Nginx 源码进行了修改 patch，分析了一下 OpenResty 的修改比较多，因此在 OpenResty 的基础上 patch 以支持 ja4-nginx-module

首先下载 OpenResty 源码

```bash
wget https://openresty.org/download/openresty-1.27.1.2.tar.gz
tar -xzvf openresty-1.27.1.2.tar.gz
cd openresty-1.27.1.2/
```

然后参考 ja4-nginx-module 里 Dockerfile 的步骤进行编译

下载 OpenSSL，这里参考 Dockerfile 使用3.5.4的版本，参考 https://github.com/FoxIO-LLC/ja4-nginx-module/pull/38 可知 OpenSSL3.0 版本开始已经能够正常工作不需要 patch。OpenResty 中也有针对 OpenSSL 的 patch，但是我们用不上那些功能，因此可以忽略

```bash
wget https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz
tar -xzvf openssl-3.5.4.tar.gz
```

下载 ja4-nginx-module

```bash
git clone https://github.com/FoxIO-LLC/ja4-nginx-module.git
```

然后应用对应的 patch

```bash
cd bundle/nginx-1.27.1/
patch -p1 < ../../ja4-nginx-module/patches/nginx.patch
```

尽管在 Dockerfile 中这个是对应 Nginx 1.28.1 的 patch，但是这里能够直接应用且编译时不会报错

![patch_nginx](https://img.0a0.moe/blog/2026/01/27/%E7%BC%96%E8%AF%91%E5%B8%A6%E6%9C%89-ja4-%E6%8C%87%E7%BA%B9%E7%9A%84-openresty/3f80a7d3bb53d349f66e679df8752622bb6ad0779c70d644d1886c43a8466b74.webp)

接下来运行 configure，可以按实际需要进行修改

```bash
cd ../../
./configure \
  --with-openssl=openssl-3.5.4 \
  --add-module=ja4-nginx-module/src \
  --with-debug \
  --with-compat \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_v3_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-pcre-jit
```

然后直接

```bash
make -j$(nproc)
```

就可以了。OpenResty 在编译的时候会顺带编译 OpenSSL，不需要我们另外去 configure 再 make。在测试过程中有次出现了报错，但重试就没了。

最后

```bash
sudo make install
```

即可完成安装

## 测试

编辑 `nginx.conf` 文件，添加上如下内容即可测试结果

```
server {
    listen 443 ssl;

    server_name localhost;

    ssl_certificate cert.pem;
    ssl_certificate_key key.pem;

    # prevent caching issue w/ signature algorithm extension
    ssl_session_cache off;

    location / {
        add_header Content-Type text/plain;
        return 200 "
        JA4: $http_ssl_ja4\n
        JA4 String: $http_ssl_ja4_string\n
        JA4one: $http_ssl_ja4one\n
        JA4S: $http_ssl_ja4s\n
        JA4S String: $http_ssl_ja4s_string\n
        JA4H: $http_ssl_ja4h\n
        JA4H String: $http_ssl_ja4h_string\n
        JA4T: $http_ssl_ja4t\n
        JA4T String: $http_ssl_ja4t_string\n
        JA4TS: $http_ssl_ja4ts\n
        JA4TS String: $http_ssl_ja4ts_string\n
        JA4X: $http_ssl_ja4x\n
        JA4L: $http_ssl_ja4l\n
        ";
    }
}
```

其中，`server_name` 以及 `ssl_certificate`、`ssl_certificate_key` 按实际配置，需要配置证书才能有 ssl，才可以有 JA4 指纹。

![ja4_result](https://img.0a0.moe/blog/2026/01/27/%E7%BC%96%E8%AF%91%E5%B8%A6%E6%9C%89-ja4-%E6%8C%87%E7%BA%B9%E7%9A%84-openresty/127044df7c755ade129e5b481cf5346793e63e9450085d2815bb4cc2c9b30241.webp)

可以看到工作正常。



## 其他

如果要使用要使用异步 SSL session，需要应用 OpenResty 里 patches 的补丁

```bash
cd openssl-3.5.4/
patch -p1 < ../patches/openssl-3.4.1-sess_set_get_cb_yield.patch
```

OpenSSL 3.5.4 可以直接应用 3.4.1 的补丁，patch 后重新 configure 和 make 编译即可