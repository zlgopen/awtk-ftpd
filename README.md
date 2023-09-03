# awtk-ftpd

## 1. 介绍

在嵌入式应用程序中，有时需要提供一个 FTP 服务，用于对系统的文件进行远程管理。

awtk-ftpd 实现了一个 简单的 FTP 服务。主要特色有：

* 小巧。约 800 行代码。
* 可以在各种嵌入式平台运行。
* 内存开销低。正常内存需求小于 6K。
* 兼容 [FTP 协议](https://www.rfc-editor.org/rfc/rfc959)，可以使用常用 FTP 客户端工具。
* 方便嵌入到 AWTK 应用程序。无缝集成到 AWTK 的主循环，无需另外开辟线程。

> 为了实现方便，目前使用单用户单连接，Passive 模式使用固定端口。

## 2 准备

### 2.1 获取 awtk 并编译

```
git clone https://github.com/zlgopen/awtk.git
cd awtk; scons; cd -
```

### 2.2 获取 awtk-ftpd 并编译

```
git clone https://github.com/zlgopen/awtk-ftpd.git
cd awtk-ftpd
```

* 生成资源

```
python ./scripts/update_res.py all
```

> 或者通过 designer 生成资源

* 编译 PC 版本

```
scons
```

* 编译 LINUX FB 版本

```
scons LINUX_FB=true
```

> 完整编译选项请参考 [编译选项](https://github.com/zlgopen/awtk-widget-generator/blob/master/docs/build_options.md)

## 3. 运行

```
./bin/demo
```

默认监听 2121 端口。

## 4. 相关项目

* [嵌入式 WEB 服务器  awtk-restful-httpd](https://github.com/zlgopen/awtk-restful-httpd)
