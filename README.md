# eTracee - 基于eBPF的系统调用监控系统

> 轻量级eBPF系统调用监控工具，实时捕获和分析系统行为

## 🎯 项目简介

**eTracee** 是一个基于eBPF技术的系统调用监控工具，专注于实时捕获和分析Linux系统的关键系统调用。项目采用现代化的eBPF CO-RE (Compile Once, Run Everywhere) 技术，提供高性能、低开销的内核级监控能力。

### 核心特性

- 🔍 **内核级监控**: 基于eBPF技术，无侵入式捕获系统调用
- ⚡ **高性能传输**: 使用Ring Buffer实现高效的内核-用户态数据传输
- 🎯 **精准监控**: 专注监控execve、openat、connect等关键系统调用
- 📊 **结构化输出**: 标准JSON格式输出，便于后续处理和分析
- 🚀 **CO-RE兼容**: 一次编译，多内核版本运行
- 🛡️ **轻量设计**: 最小化系统资源占用和性能影响

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Linux Kernel Space                      │
├─────────────────────────────────────────────────────────────┤
│  eBPF Program (probe.c)                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ execve tracepoint│  │openat tracepoint│  │connect trace│ │
│  │                 │  │                 │  │   point     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
│                           │                                │
│                           ▼                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Ring Buffer (256KB)                       │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼ (高效数据传输)
┌─────────────────────────────────────────────────────────────┐
│                    User Space                              │
├─────────────────────────────────────────────────────────────┤
│  Go Program (ebpf_receiver)                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │  Event Parser   │  │ Timestamp Fix   │  │JSON Output  │ │
│  │                 │  │                 │  │             │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
│                           │                                │
│                           ▼                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │         Structured JSON Event Stream                   │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 快速开始

### 系统要求

- **操作系统**: Linux (内核版本 >= 4.18，支持eBPF CO-RE)
- **编译环境**: clang, llvm, libbpf-dev
- **运行权限**: root权限或CAP_BPF能力
- **Go版本**: >= 1.19
- **内存**: >= 1GB RAM
- **存储**: >= 500MB 可用空间

### 环境准备

#### Ubuntu/Debian系统
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev bpftool
```

#### CentOS/RHEL/openEuler系统
```bash
sudo yum install -y clang llvm libbpf-devel bpftool
```

### 编译安装

```bash
# 克隆项目
git clone https://github.com/2577552541/eTracee.git
cd eTracee

# 一键构建
make

# 或分步构建
make ebpf      # 编译eBPF程序
make go-build  # 构建Go程序
```

### 运行监控

```bash
# 启动系统调用监控 (需要root权限)
sudo ./bin/ebpf_receiver
```

### 验证安装

```bash
# 检查构建状态
make status

# 运行基础测试
make test
```

## 📁 项目结构

```
eTracee/
├── Makefile                    # 项目主构建文件
├── README.md                   # 项目文档
├── bin/                        # 编译输出目录
│   └── ebpf_receiver          # Go用户态程序
├── bpf/                        # eBPF内核程序
│   ├── Makefile               # eBPF构建文件
│   └── probe.c                # eBPF监控程序
├── cmd/                        # Go程序源码
│   └── ebpf_receiver/         # 用户态事件接收器
│       ├── go.mod             # Go模块依赖
│       ├── go.sum             # 依赖校验文件
│       └── main.go            # 主程序文件
├── docs/                       # 技术文档
│   └── week1-2-implementation.md
├── test/                       # 测试脚本
│   ├── execve_trace.bt        # bpftrace测试脚本
│   ├── ingest_realtime.py     # Python数据采集器
│   ├── test_result.log        # 测试结果日志
│   └── trigger_exec.sh        # 测试事件触发器
└── setup-ebpf.sh              # 环境安装脚本
```

## 🔧 技术实现

### eBPF程序特性

**监控的系统调用:**
- `execve`: 进程执行监控，捕获新进程启动
- `openat`: 文件访问监控，跟踪文件操作
- `connect`: 网络连接监控，检测网络活动

**事件数据结构:**
```c
struct event {
    u64 timestamp;      // 时间戳 (纳秒)
    u32 pid;           // 进程ID
    u32 ppid;          // 父进程ID
    u32 uid;           // 用户ID
    u32 gid;           // 组ID
    u32 event_type;    // 事件类型 (1=execve, 2=openat, 3=connect)
    char comm[16];     // 进程名
    char filename[256]; // 文件名/路径
    u32 syscall_nr;    // 系统调用号
    s32 ret_code;      // 返回码
};
```

### JSON输出格式

```json
{
  "timestamp": 1640995200123456789,
  "time_str": "2022-01-01 12:00:00.123456",
  "pid": 1234,
  "ppid": 1000,
  "uid": 1000,
  "gid": 1000,
  "event_type": 1,
  "event_name": "execve",
  "comm": "bash",
  "filename": "/bin/ls",
  "syscall_nr": 59,
  "ret_code": 0
}
```

### 关键技术特点

1. **CO-RE技术**: 使用BTF实现内核版本兼容性
2. **Ring Buffer**: 高效的内核-用户态数据传输
3. **时间戳处理**: 准确转换eBPF时间戳为实际时间
4. **内存对齐**: 精确匹配内核和用户态数据结构
5. **优雅退出**: 完善的信号处理和资源清理

## 🛠️ 使用指南

### 基础监控

```bash
# 启动实时监控
sudo ./bin/ebpf_receiver

# 输出重定向到文件
sudo ./bin/ebpf_receiver > events.json

# 结合jq进行实时分析
sudo ./bin/ebpf_receiver | jq '.event_name'
```

### 过滤特定事件

```bash
# 只监控execve事件
sudo ./bin/ebpf_receiver | jq 'select(.event_name == "execve")'

# 监控特定用户的活动
sudo ./bin/ebpf_receiver | jq 'select(.uid == 1000)'

# 监控文件访问
sudo ./bin/ebpf_receiver | jq 'select(.event_name == "openat")'
```

### 开发和调试

```bash
# 查看项目状态
make status

# 清理重新构建
make clean && make

# 开发模式运行
make dev
```

## 🔍 监控能力

当前实现可以检测以下系统行为：

### 进程活动监控
- 新进程启动 (execve)
- 进程执行链跟踪
- 父子进程关系分析

### 文件系统监控
- 文件打开操作 (openat)
- 敏感文件访问检测
- 文件访问模式分析

### 网络活动监控
- 网络连接建立 (connect)
- 异常网络行为检测
- 进程网络活动关联

## 🚧 开发路线图

### 已完成功能 ✅
- [x] eBPF内核程序实现
- [x] Ring Buffer数据传输
- [x] Go用户态事件处理
- [x] JSON标准化输出
- [x] 时间戳准确转换
- [x] 完整构建系统

### 计划功能 🔄
- [ ] 事件过滤和聚合
- [ ] 轻量级规则引擎
- [ ] 数据存储后端
- [ ] Web可视化界面
- [ ] 攻击链分析
- [ ] 异常检测算法

## 🤝 贡献指南

欢迎贡献代码和建议！请遵循以下步骤：

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [eBPF 社区](https://ebpf.io/) - 提供强大的内核编程框架
- [cilium/ebpf](https://github.com/cilium/ebpf) - 优秀的Go eBPF库
- [libbpf](https://github.com/libbpf/libbpf) - eBPF用户态库

## 📞 联系方式

- 项目主页: https://github.com/2577552541/eTracee
- 问题反馈: https://github.com/2577552541/eTracee/issues

---

**eTracee** - 让系统行为一目了然 🔍