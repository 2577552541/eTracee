# eTracee 项目主构建文件
# 统一管理eBPF程序编译和Go程序构建

.PHONY: all build clean ebpf go-build test install help

# 默认目标
all: build

# 构建整个项目
build: ebpf go-build

# 编译eBPF程序
ebpf:
	@echo "正在编译eBPF程序..."
	@cd bpf && $(MAKE)
	@echo "eBPF程序编译完成"

# 构建Go程序
go-build: ebpf
	@echo "正在构建Go用户态程序..."
	@cd cmd/ebpf_receiver && go mod tidy
	@cd cmd/ebpf_receiver && go build -o ../../bin/ebpf_receiver .
	@echo "Go程序构建完成: bin/ebpf_receiver"

# 创建bin目录
bin:
	@mkdir -p bin

# 运行测试
test: build
	@echo "运行基础测试..."
	@if [ -f "bin/ebpf_receiver" ]; then \
		echo "✓ ebpf_receiver 可执行文件存在"; \
	else \
		echo "✗ ebpf_receiver 可执行文件不存在"; \
		exit 1; \
	fi
	@if [ -f "bpf/probe.o" ]; then \
		echo "✓ probe.o eBPF对象文件存在"; \
	else \
		echo "✗ probe.o eBPF对象文件不存在"; \
		exit 1; \
	fi
	@echo "基础测试通过"

# 清理生成的文件
clean:
	@echo "清理生成的文件..."
	@cd bpf && $(MAKE) clean
	@rm -rf bin/
	@cd cmd/ebpf_receiver && go clean
	@echo "清理完成"

# 安装依赖
install:
	@echo "安装Go依赖..."
	@cd cmd/ebpf_receiver && go mod download
	@echo "请确保在Linux环境下安装eBPF依赖:"
	@echo "  sudo apt-get install -y clang llvm bpftool libbpf-dev"
	@echo "  或在openEuler系统下:"
	@echo "  sudo yum install -y clang llvm bpftool libbpf-devel"

# 开发模式运行
dev: build
	@echo "开发模式运行 (需要在Linux环境下执行):"
	@echo "sudo ./bin/ebpf_receiver"

# 显示项目状态
status:
	@echo "=== eTracee 项目状态 ==="
	@echo "项目结构:"
	@echo "  bpf/probe.c     - eBPF内核程序"
	@echo "  cmd/ebpf_receiver/ - Go用户态程序"
	@echo "  test/           - 测试脚本"
	@echo ""
	@echo "构建状态:"
	@if [ -f "bpf/probe.o" ]; then \
		echo "  ✓ eBPF程序已编译"; \
	else \
		echo "  ✗ eBPF程序未编译"; \
	fi
	@if [ -f "bin/ebpf_receiver" ]; then \
		echo "  ✓ Go程序已构建"; \
	else \
		echo "  ✗ Go程序未构建"; \
	fi

# 显示帮助信息
help:
	@echo "eTracee - 面向国产操作系统的轻量级eBPF攻击链可视化系统"
	@echo ""
	@echo "可用目标:"
	@echo "  all      - 构建整个项目 (默认)"
	@echo "  build    - 构建eBPF程序和Go程序"
	@echo "  ebpf     - 仅编译eBPF程序"
	@echo "  go-build - 仅构建Go程序"
	@echo "  test     - 运行基础测试"
	@echo "  clean    - 清理生成的文件"
	@echo "  install  - 安装依赖"
	@echo "  dev      - 开发模式运行"
	@echo "  status   - 显示项目状态"
	@echo "  help     - 显示此帮助信息"
	@echo ""
	@echo "使用示例:"
	@echo "  make           # 构建整个项目"
	@echo "  make clean     # 清理所有生成的文件"
	@echo "  make test      # 运行测试"
	@echo "  make status    # 查看项目状态"
	@echo ""
	@echo "注意: eBPF程序需要在Linux环境下编译和运行"