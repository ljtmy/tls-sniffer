# tls-sniffer

基于 eBPF uprobe 的 TLS/SSL 明文抓包工具。通过在用户态挂载 `SSL_write`、`SSL_read` 等函数的探针，在数据加密前（发送）和解密后（接收）捕获 TLS 通信的明文内容，无需解密密钥。

## 项目作用

在 HTTPS/TLS 通信调试中，传统抓包工具（如 Wireshark）只能获取密文，需要配置密钥日志才能解密。tls-sniffer 从另一个角度解决问题：直接在 OpenSSL 等 TLS 库的函数调用处拦截明文数据，实现：

- **无需密钥** — 不依赖 SSLKEYLOGFILE 或服务端私钥
- **无侵入** — 不修改目标进程，不中断 TLS 连接
- **双向捕获** — 同时捕获发送和接收的明文
- **进程级过滤** — 精确到指定 PID 或进程名
- **多种输出** — 终端文本、JSON Lines、PCAP 文件（可用 Wireshark 分析）
- **HTTP 解析** — 自动从 TLS 明文中提取 HTTP 请求/响应
- **多库支持** — OpenSSL、BoringSSL、GnuTLS

典型使用场景：调试 HTTPS API 调用、分析加密通信内容、安全审计与教学研究。

## 环境要求

| 依赖 | 版本要求 | 说明 |
|------|---------|------|
| Linux 内核 | >= 5.8 | 需要 BTF 支持（`/sys/kernel/btf/vmlinux`） |
| Go | >= 1.22 | 编译用户态程序 |
| Clang/LLVM | >= 11 | 编译 eBPF 程序 |
| bpftool | 任意版本 | 生成 `vmlinux.h` |
| root 权限 | — | 加载 eBPF 程序需要 CAP_BPF |

检查环境：

```bash
uname -r                          # 内核版本 >= 5.8
ls /sys/kernel/btf/vmlinux        # BTF 存在
go version                        # Go >= 1.22
clang --version                   # Clang >= 11
bpftool version                   # bpftool 可用
```

## 项目文件结构

```
tls-sniffer/
├── Makefile                          # 构建脚本（BPF 编译 + Go 编译）
├── go.mod                            # Go 模块定义
├── test_integration.sh               # 集成测试脚本
├── bpf/
│   ├── sniffer.h                     # 共享结构体定义（tls_event, read_state）
│   ├── sniffer.bpf.c                 # eBPF 探针程序（6 个 uprobe/uretprobe）
│   └── vmlinux.h                     # 自动生成的内核类型定义
├── cmd/
│   └── sniffer/
│       └── main.go                   # CLI 入口：参数解析、流程编排
└── internal/
    ├── event/
    │   ├── event.go                  # TLSEvent 结构体 + Assembler 部分读取重组
    │   ├── http.go                   # HTTP/1.x 请求/响应解析
    │   ├── json.go                   # JSON Lines 格式输出
    │   ├── pcap.go                   # PCAP 文件输出（伪 TCP/IP 封装）
    │   ├── stdout.go                 # 终端文本输出
    │   ├── event_test.go             # Assembler 单元测试
    │   ├── http_test.go              # HTTP 解析单元测试
    │   └── json_test.go              # JSON 输出单元测试
    ├── loader/
    │   └── loader.go                 # BPF 程序加载、探针附加、Ring Buffer 读取
    └── resolver/
        ├── resolver.go               # ELF 符号解析（查找 libssl，解析函数偏移）
        ├── conntrack.go              # 连接跟踪（SSL* → TCP 五元组映射）
        └── conntrack_test.go         # 连接跟踪单元测试
```

## 快速开始

### 1. 编译

```bash
# 生成 vmlinux.h（首次需要）
make vmlinux

# 编译 eBPF 程序和 Go 二进制
make
```

编译产物：
- `bpf/sniffer.bpf.o` — eBPF 字节码
- `bin/sniffer` — 用户态工具

### 2. 运行

```bash
# 基本用法：指定目标进程 PID
sudo ./bin/sniffer --pid <PID>

# 按进程名自动查找 PID
sudo ./bin/sniffer --pid <PID> --comm curl

# 按 PID 列表过滤
sudo ./bin/sniffer --pid <PID> --pids 1234,5678
```

### 3. 输出格式

```bash
# 终端文本输出（默认）
sudo ./bin/sniffer --pid <PID> --output text

# JSON Lines 输出（便于管道处理）
sudo ./bin/sniffer --pid <PID> --output json | jq .

# PCAP 文件输出（用 Wireshark 分析）
sudo ./bin/sniffer --pid <PID> --output pcap --pcap-file capture.pcap
```

### 4. 示例：抓取 curl 的 HTTPS 请求

```bash
# 终端 1：启动一个长时间运行的 curl
curl -s --max-time 60 https://example.com > /dev/null &

# 终端 2：抓包
sudo ./bin/sniffer --pid $! --output text
```

输出示例：

```
[*] Found /usr/lib/x86_64-linux-gnu/libssl.so.3 (OpenSSL)
    SSL_write @ 0x36b20
    SSL_read @ 0x365b0
[*] Attached probes to 1 library(ies)
[*] Listening for TLS events... Press Ctrl+C to stop.

--- TLS SEND ---
Time: 2026-05-12 14:13:43.562
PID: 20301  TID: 20301  COMM: curl  Len: 57
HTTP: GET / HTTP/1.1
  Host: example.com
  Connection: close
```

## 工作原理

```
目标进程 (curl/openssl/...)
    │
    │  SSL_write(ssl, buf, len)
    │  SSL_read(ssl, buf, len)
    │  SSL_set_fd(ssl, fd)
    ▼
┌─────────────────────────┐
│   eBPF uprobe/uretprobe │  ← 内核态，拦截函数调用
│   读取 buf 明文数据      │
│   通过 Ring Buffer 提交  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   Go 用户态程序          │
│   ├ Assembler 重组分片   │
│   ├ HTTP 解析            │
│   ├ 连接跟踪             │
│   └ 输出 (text/json/pcap)│
└─────────────────────────┘
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--pid` | （必填） | 目标进程 PID（用于符号解析） |
| `--pids` | 空 | 逗号分隔的 PID 列表（BPF 侧过滤） |
| `--comm` | 空 | 进程名过滤（自动从 `/proc` 查找 PID） |
| `--bpf` | `bpf/sniffer.bpf.o` | BPF 对象文件路径 |
| `--output` | `text` | 输出格式：`text`、`json`、`pcap` |
| `--pcap-file` | `output.pcap` | PCAP 输出文件路径 |

## 运行测试

```bash
# 单元测试
go test ./internal/event/ ./internal/resolver/ -v

# 集成测试（需要 root）
sudo bash test_integration.sh
```

## License

MIT
