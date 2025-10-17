# eBPF程序构建配置
# 适用于 eTracee 项目

# 编译器和工具
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# 编译标志
CFLAGS := -O2 -g -Wall -Werror
CFLAGS += -target bpf
CFLAGS += -D__TARGET_ARCH_x86
CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS += -I.

# 源文件和目标文件
SOURCES := probe.c
OBJECTS := $(SOURCES:.c=.o)

# 默认目标
all: $(OBJECTS) vmlinux.h

# 编译eBPF程序
%.o: %.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# 生成vmlinux.h头文件
vmlinux.h:
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
		echo "Generated vmlinux.h using bpftool"; \
	else \
		echo "Warning: bpftool not found, using fallback vmlinux.h"; \
		echo "/* Fallback vmlinux.h - minimal definitions */" > vmlinux.h; \
		echo "#ifndef __VMLINUX_H__" >> vmlinux.h; \
		echo "#define __VMLINUX_H__" >> vmlinux.h; \
		echo "typedef unsigned char u8;" >> vmlinux.h; \
		echo "typedef unsigned short u16;" >> vmlinux.h; \
		echo "typedef unsigned int u32;" >> vmlinux.h; \
		echo "typedef unsigned long long u64;" >> vmlinux.h; \
		echo "typedef signed int s32;" >> vmlinux.h; \
		echo "struct task_struct { int tgid; struct task_struct *real_parent; };" >> vmlinux.h; \
		echo "struct trace_event_raw_sys_enter { unsigned short common_type; unsigned char common_flags; unsigned char common_preempt_count; int common_pid; int id; unsigned long args[6]; };" >> vmlinux.h; \
		echo "struct trace_event_raw_sys_exit { unsigned short common_type; unsigned char common_flags; unsigned char common_preempt_count; int common_pid; int id; long ret; };" >> vmlinux.h; \
		echo "#endif" >> vmlinux.h; \
	fi

# 清理生成的文件
clean:
	rm -f *.o vmlinux.h

# 安装依赖（仅在Linux环境下有效）
install-deps:
	@echo "请在Linux环境下运行以下命令安装依赖："
	@echo "sudo apt-get update"
	@echo "sudo apt-get install -y clang llvm bpftool libbpf-dev"
	@echo "或者在openEuler系统下："
	@echo "sudo yum install -y clang llvm bpftool libbpf-devel"

# 验证eBPF程序
verify: $(OBJECTS)
	@for obj in $(OBJECTS); do \
		echo "验证 $$obj..."; \
		if command -v $(BPFTOOL) >/dev/null 2>&1; then \
			$(BPFTOOL) prog load $$obj /sys/fs/bpf/test_$$obj 2>/dev/null && \
			echo "$$obj 验证成功" && \
			rm -f /sys/fs/bpf/test_$$obj || \
			echo "$$obj 验证失败"; \
		else \
			echo "bpftool 不可用，跳过验证"; \
		fi; \
	done

# 显示帮助信息
help:
	@echo "eTracee eBPF 构建系统"
	@echo ""
	@echo "可用目标："
	@echo "  all          - 编译所有eBPF程序 (默认)"
	@echo "  clean        - 清理生成的文件"
	@echo "  install-deps - 显示依赖安装命令"
	@echo "  verify       - 验证编译的eBPF程序"
	@echo "  help         - 显示此帮助信息"
	@echo ""
	@echo "示例："
	@echo "  make         - 编译probe.c为probe.o"
	@echo "  make clean   - 清理所有生成的文件"
	@echo "  make verify  - 验证编译的程序"

.PHONY: all clean install-deps verify help