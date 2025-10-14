# 实验报告

## ℹ️ 简介

TermShark 是一个在终端中使用的“迷你版 WireShark”，基于 Rust 开发，目标是：

- 通过 `pcap` 从网卡或 `.pcap` 文件获取数据包
- 用 TUI（`ratatui`）展示三栏视图：数据包列表、协议细节、十六进制转储
- 支持简单易懂的 GitHub 风格过滤语法（`key:value`）进行实时过滤

本项目为课程/实验性质，功能刻意保持精简，以保证代码结构清晰、可读性与可维护性强。

仓库主要依赖：

- `pcap`（抓包/读包）
- `ratatui`（终端 UI）
- `argh`（命令行解析）

参考与样本：使用 WireShark 官方 [SampleCaptures](https://wiki.wireshark.org/SampleCaptures) 提供的样本包进行验证与演示。

## 🌲 设计框架

### 模块划分

- CLI 层 (`src/cli.rs`)
    - 子命令：`capture` (从设备抓包)、`list` (列出设备)、`load <file>` (从 pcap 文件读取)
- 应用层 (`src/app`)
    - `state.rs`：应用状态 `App` (数据、过滤状态、UI 滚动与当前选择等)
    - `events.rs`：键盘事件处理 (导航、滚动、应用/清除过滤等)
    - `ui.rs`：UI 渲染 (过滤、表格、详情、十六进制与帮助栏)
    - `filter.rs`：过滤器的解析与匹配
    - `packet_info.rs`：展示层数据模型
- 以太网解析层 (`src/ethernet`)
    - 统一的协议描述 API：`PacketDetail` trait
    - 具体协议：`EthernetPacket` → `Ipv4Packet`/`Ipv6Packet`/`ArpPacket` → `ICMPPacket`/`IGMPPacket`/`TCPPacket`/`UDPPacket` → 应用层协议

### 协议层级

- `EthernetPacket`
    - `Ipv4Packet`
        - `IcmpPacket`
        - `IgmpPacket`
        - `TcpPacket`
            - `HttpPacket`
            - `UnknownTcpPacket`
        - `UdpPacket`
            - `DNSPacket` (DNS + mDNS)
            - `UnknownUdpPacket`
        - `UnknownIpv4Packet`
    - `ArpPacket`
    - `Ipv6Packet`
    - `UnknownEthernetPacket`

每一层实现 `PacketDetail`，并通过 `inner()` 访问下一层，形成“协议链”。展示时：

- 列表中“Protocol/Info”展示链中最深的一层 (如 TCP/ICMP 等)
- 由于部分协议不包含源/目的地址，因此选择协议链中最深的源/目的地址展示
- 详情区域按层自上而下展开

### 主循环 (`app::run`)

1. 通过 [`pcap`](https://crates.io/crates/pcap) 非阻塞读取所有可用数据包
2. 解析获取的包为 `EthernetPacket`，并提取相关信息 `PacketInfo`
3. 缓存相关信息，按需写入 savefile
4. 绘制 TUI，并处理键盘事件

## 💻 开发过程

主要的开发过程：

1. 设备枚举 (`e164455`)
2. 命令行参数读取 (`d2d0e28`)
3. 以太网包解析 (`0f2131b`)
4. ARP, IPv4 包解析 (`160dc4d`, `e13b490`)
5. 基本的 TUI 实现 (`311af9a`)
6. ICMP, UDP, TCP, IPV6 包解析 (`2217d5d` - `761ad8b`)
7. 代码重构与优化
8. IGMP 包解析 (`3127026`)
9. 包过滤功能 (`02fa902`)
10. 细节改进
11. DNS, mDNS 包解析 (`2e88e62`, `49c7747`)
12. HTTP 包解析 (`eff279f` - `ee0a81d`)

难点与解决：

- 非阻塞抓包：通过 [`setnonblock`](https://docs.rs/pcap/2.3.0/pcap/struct.Capture.html#method.setnonblock) 避免阻塞进程
- 地址与协议的展示：遍历协议链获取“最深层协议”与“最后一层有效地址”

测试与验证：

- 集成测试 `tests/integration_test.rs`：对示例封包 (`samples/*.pcap`) 逐个解析并确保不报错
- 过滤语法在 `src/app/filter.rs` 中编写了单元测试用例（如长度范围/比较、复合条件等）

## 📖 操作指南

### 运行

列出设备：

```bash
./target/release/termshark list
```

抓包 (需要 root 或通过 setcap 配置权限)：

```bash
sudo ./target/release/termshark capture
```

指定设备抓包并保存：

```bash
sudo ./target/release/termshark capture -d <interface> -s out.pcap
```

加载已有 pcap 文件：

```bash
./target/release/termshark load samples/HTTP.pcap
```

### 键盘快捷键

- 导航：↑/↓ 或 j/k；PageUp/Down；Home/End
- 滚动详情/十六进制：w/s 与 e/d
- 过滤：Enter 进入/应用过滤；Esc 清除或取消；Backspace 编辑时删除末尾字符
- 退出：q 或 Ctrl+C

### 过滤语法

基本格式：`searchterm key:value key2:value2`（不同 key 之间 AND，同 key 多值用逗号 OR）

- `protocol`/`proto`：如 `protocol:tcp` 或 `proto:icmp,udp`
- `source`/`src`：源地址精确匹配，如 `source:192.168.1.1`
- `destination`/`dest`/`dst`：目的地址精确匹配，如 `dst:8.8.8.8`
- `length`/`len`：长度比较与范围，示例：`len:>1000`、`length:<500`、`len:100-1500`

示例：

```text
protocol:tcp,udp                       # TCP 或 UDP
source:192.168.1.100                   # 指定源
protocol:tcp length:>1000              # 大包 TCP
HTTP source:192.168.1.1                # 给定 IP 的包含 "HTTP" 的流量
protocol:icmp,arp length:<100          # 小包 ICMP/ARP
```

## 📃 总结

本项目实现了一个结构清晰的终端抓包与离线分析工具：

- 协议解析采用“链式”层级设计，`PacketDetail` 统一接口，展示层详情数据与 UI 解耦
- TUI 交互自然流畅，支持实时过滤、滚动、分页与即时错误提示
- CLI 具备在线抓包、列设备与离线加载三种工作流，同时支持保存文件
- 使用公共样本进行了验证，集成测试通过，具备基本稳定性

后续工作：

- 十六进制偏移与字节可考虑统一大写显示
- 更丰富的滚动与分区切换体验 (滚轮、Tab 等)
- 统计面板、TCP 流追踪、HTTP 重组等高级功能
- 实现 WireShark 过滤语法 (可考虑使用 `wirefilter`)

收获与体会：

- Rust 的类型系统与 trait 抽象非常适合协议栈这种“分层 + 组合”的问题
- TUI 开发中“状态与渲染解耦”能显著降低复杂度
- 小而清晰的过滤语法能大幅提升可用性

附：主要文件与职责

- `src/main.rs`：入口，调度 CLI 与运行 TUI
- `src/cli.rs`：命令行参数解析 (capture/list/load)
- `src/app/*`：事件、状态、UI、过滤、展示模型
- `src/ethernet/*`：协议解析实现
- `tests/integration_test.rs`：样本包解析集成测试
