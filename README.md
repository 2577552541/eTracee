# 鹰眼追踪 (EagleTrace)

> 基于 eBPF 和轻量 AI 的攻击链可视化系统，专为国产操作系统 openEuler 25.09 设计

## 🎯 项目简介

**鹰眼追踪 (EagleTrace)** 是一个创新的网络安全监控与分析平台，利用 eBPF 技术实现内核级系统调用捕获，结合轻量级人工智能算法，为安全分析师提供实时的攻击链可视化和异常检测能力。

### 核心特性

- 🔍 **内核级监控**: 基于 eBPF 技术，无侵入式捕获系统调用和内核事件
- 🧠 **智能分析**: 集成轻量级 AI 模型，自动识别异常行为模式
- 📊 **可视化图谱**: 实时构建和展示攻击链关系图谱
- 🎨 **直观界面**: 现代化 Web 界面，支持交互式数据探索
- 🚀 **高性能**: 针对国产操作系统优化，低延迟高吞吐
- 🛡️ **安全加固**: 遵循最佳安全实践，支持权限最小化部署

## 🏗️ 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   eBPF 内核模块  │───▶│   数据采集层     │───▶│   规则引擎       │
│  (syscall捕获)  │    │  (Go/Python)   │    │  (实时匹配)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   前端可视化     │◀───│   数据存储层     │◀───│   AI 分析引擎    │
│  (D3.js/React) │    │   (SQLite)     │    │ (异常检测/评分)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 快速开始

### 系统要求

- **操作系统**: openEuler 25.09 (推荐) 或其他支持 eBPF 的 Linux 发行版
- **内核版本**: >= 4.18 (支持 eBPF CO-RE)
- **权限**: root 或具有 CAP_BPF 能力
- **内存**: >= 4GB RAM
- **存储**: >= 5GB 可用空间

### 一键安装

```bash
# 克隆项目
git clone https://github.com/2577552541/eTracee.git
cd eTracee

# 执行自动化安装脚本
sudo bash setup-ebpf.sh
```

安装脚本将自动完成：
- ✅ 系统依赖检查和安装 (clang, llvm, bpftool, bpftrace 等)
- ✅ 内核 eBPF 支持验证
- ✅ 开发环境配置
- ✅ 示例程序部署和测试

### 验证安装

安装完成后，检查 `test/test_result.log` 文件确认系统正常工作：

```bash
# 查看测试结果
cat test/test_result.log

# 手动运行测试
sudo bpftrace test/execve_trace.bt &
bash test/trigger_exec.sh
```

预期输出示例：
```
bash -> /bin/ls
bash -> /bin/true
bash -> /usr/bin/sleep
...
```

## 📁 项目结构

```
EagleTrace/
├── setup-ebpf.sh          # 一键安装脚本
├── setup-ebpf.log         # 安装日志
├── test/                  # 测试和示例
│   ├── execve_trace.bt    # bpftrace 系统调用跟踪脚本
│   ├── ingest_realtime.py # Python 实时数据采集器
│   ├── trigger_exec.sh    # 测试事件触发器
│   └── test_result.log    # 测试执行日志
├── src/                   # 源代码 (开发中)
│   ├── ebpf/             # eBPF 内核程序
│   ├── collector/        # 用户态数据收集器
│   ├── engine/           # 规则引擎和 AI 模块
│   ├── api/              # REST API 服务
│   └── frontend/         # Web 前端界面
└── docs/                 # 文档 (开发中)
```

## 🛠️ 开发计划

### 第一阶段 (周 1-4): 基础设施
- [x] 环境准备和 eBPF 最简可行链路
- [ ] 系统调用捕获和数据导出
- [ ] 过滤规则和聚合功能
- [ ] 轻量级规则引擎

### 第二阶段 (周 5-8): 数据处理
- [ ] 事件存储与索引系统
- [ ] 后端架构和 WebSocket 接口
- [ ] 关系图谱模型构建
- [ ] 前端可视化 PoC

### 第三阶段 (周 9-11): 可视化
- [ ] 图谱交互和时间回放
- [ ] 轻量 AI 特征工程
- [ ] AI 与规则引擎联动

### 第四阶段 (周 12-14): 完善
- [ ] 自动化报告生成
- [ ] 性能优化和安全加固
- [ ] 文档完善和最终交付

## 🔧 使用指南

### 基础监控

```bash
# 启动实时系统调用监控
sudo python3 test/ingest_realtime.py

# 在另一个终端触发测试事件
bash test/trigger_exec.sh
```

### 自定义规则

编辑 bpftrace 脚本以监控特定事件：

```bash
# 监控文件打开操作
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_openat {
    printf("%s opened: %s\n", comm, str(args->filename));
}'
```

### 高级配置

详细配置选项请参考 [配置文档](docs/configuration.md) (开发中)

## 🤝 贡献指南

我们欢迎社区贡献！请遵循以下步骤：

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [eBPF 社区](https://ebpf.io/) - 提供强大的内核编程框架
- [bpftrace 项目](https://github.com/iovisor/bpftrace) - 高级 eBPF 跟踪语言
- [openEuler 社区](https://www.openeuler.org/) - 优秀的国产操作系统平台

## 📞 联系我们

- 项目主页: https://github.com/2577552541/eTracee.git
- 问题反馈: https://github.com/2577552541/eTracee.git/issues
- 邮箱: security@your-org.com

---

**鹰眼追踪 (EagleTrace)** - 让安全威胁无所遁形 🦅