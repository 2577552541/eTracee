#!/usr/bin/env bash
# ======================================================
# eTracee 一键环境安装脚本（openEuler 25.09）
# 目标：安装 eBPF 开发环境 + 生成测试文件至 test/
# ======================================================

set -e
set -o pipefail
IFS=$'\n'

PROJECT_ROOT=$(pwd)
LOG_FILE="$PROJECT_ROOT/setup-ebpf.log"
TEST_DIR="$PROJECT_ROOT/test"

echo "=== eTracee 环境初始化开始... ==="
echo "日志文件: $LOG_FILE"
echo "当前路径: $PROJECT_ROOT"

# -----------------------
# 1 基础系统信息
# -----------------------
if [[ ! -f /etc/os-release ]]; then
  echo "无法检测操作系统信息，退出。"
  exit 1
fi

. /etc/os-release
echo "系统: $PRETTY_NAME"
echo "内核: $(uname -r)"

# -----------------------
# 2 更新并安装依赖
# -----------------------
echo "更新 dnf 缓存..."
dnf clean all -y >> "$LOG_FILE" 2>&1
dnf makecache -y >> "$LOG_FILE" 2>&1

echo "安装 eBPF 所需依赖..."
dnf install -y clang llvm elfutils-libelf-devel zlib-devel \
  kernel-headers kernel-devel bpftool bpftrace bcc-tools \
  python3 python3-pip golang git make gcc gcc-c++ sqlite sqlite-devel docker \
  >> "$LOG_FILE" 2>&1 || { echo "[!]依赖安装失败"; exit 1; }
echo "依赖安装完成。"

# -----------------------
# 3 工具版本检查
# -----------------------
echo "检查关键工具版本..."
for cmd in clang bpftool bpftrace python3 go sqlite3; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo -n "$cmd: "
    case "$cmd" in
      go) go version ;;
      *) "$cmd" --version | head -n 1 ;;
    esac
  else
    echo "[!]未找到 $cmd"
    exit 1
  fi
done

# -----------------------
# 4 检查内核 eBPF 支持
# -----------------------
echo "检查内核 eBPF 支持..."
if zgrep -q "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r); then
  echo "内核支持 eBPF。"
else
  echo "[!]当前内核不支持 eBPF，请重新编译或更新。"
  exit 1
fi

# -----------------------
# 5 创建测试目录和样例
# -----------------------
echo "初始化 test 目录..."
mkdir -p "$TEST_DIR"
chmod -R a+rwX "$TEST_DIR"

# execve trace 样例
cat > "$TEST_DIR/execve_trace.bt" <<'EOF'
#!/usr/bin/env bpftrace
tracepoint:syscalls:sys_enter_execve
{
    printf("%s -> %s\n", comm, str(args->filename));
}
EOF
chmod +x "$TEST_DIR/execve_trace.bt"

# Python 样例：实时捕获日志
cat > "$TEST_DIR/ingest_realtime.py" <<'EOF'
#!/usr/bin/env python3
import subprocess
import datetime

print("[eTracee] Realtime BPF Trace Log:")
print("---------------------------------")

cmd = ["bpftrace", "test/execve_trace.bt"]
with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
    try:
        for line in proc.stdout:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {line.strip()}")
    except KeyboardInterrupt:
        proc.terminate()
EOF
chmod +x "$TEST_DIR/ingest_realtime.py"

echo "样例文件已创建于 $TEST_DIR"

# -----------------------
# 6 bpftrace 环境验证
# -----------------------
echo "执行 bpftrace 功能验证（5秒）..."
if sudo timeout 5s bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s -> %s\n", comm, str(args->filename)); }'; then
  echo "bpftrace 功能验证通过。"
else
  echo "[!]bpftrace 测试失败（可能是权限或 SELinux）。请稍后手动运行 test/execve_trace.bt 验证。"
fi

# -----------------------
# 7 清理交互提示
# -----------------------
echo
read -p "是否要删除 test/ 测试目录？(y/N): " ans
if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
  rm -rf "$TEST_DIR"
  echo "已删除 test 目录。"
else
  echo "保留 test 目录，可用于手动测试。"
fi

echo
echo "=== eTracee-China 环境初始化完成 ==="
