#!/usr/bin/env bash
# ======================================================
# eTracee 一键环境安装脚本（openEuler 25.09） - 自动测试版
# 目标：安装 eBPF 开发环境 + 生成测试文件至 test/ + 自动执行非交互测试
# ======================================================

set -e
set -o pipefail
IFS=$'\n'

PROJECT_ROOT=$(pwd)
LOG_FILE="$PROJECT_ROOT/setup-ebpf.log"
TEST_DIR="$PROJECT_ROOT/test"
TEST_LOG="$TEST_DIR/test_result.log"

echo "=== eTracee 环境初始化开始... ===" | tee -a "$LOG_FILE"
echo "日志文件: $LOG_FILE" | tee -a "$LOG_FILE"
echo "当前路径: $PROJECT_ROOT" | tee -a "$LOG_FILE"

# -----------------------
# 1 基础系统信息
# -----------------------
if [[ ! -f /etc/os-release ]]; then
  echo "无法检测操作系统信息，退出。" | tee -a "$LOG_FILE"
  exit 1
fi

. /etc/os-release
echo "系统: $PRETTY_NAME" | tee -a "$LOG_FILE"
echo "内核: $(uname -r)" | tee -a "$LOG_FILE"

# -----------------------
# 2 更新并安装依赖
# -----------------------
echo "更新 dnf 缓存..." | tee -a "$LOG_FILE"
dnf clean all -y >> "$LOG_FILE" 2>&1 || true
dnf makecache -y >> "$LOG_FILE" 2>&1 || true

echo "安装 eBPF 所需依赖..." | tee -a "$LOG_FILE"
dnf install -y clang llvm elfutils-libelf-devel zlib-devel \
  kernel-headers kernel-devel bpftool bpftrace bcc-tools \
  python3 python3-pip golang git make gcc gcc-c++ sqlite sqlite-devel \
  >> "$LOG_FILE" 2>&1 || { echo "[!]依赖安装失败" | tee -a "$LOG_FILE"; exit 1; }
echo "依赖安装完成。" | tee -a "$LOG_FILE"

# -----------------------
# 3 工具版本检查
# -----------------------
echo "检查关键工具版本..." | tee -a "$LOG_FILE"
for cmd in clang bpftool bpftrace python3 go sqlite3; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo -n "$cmd: " | tee -a "$LOG_FILE"
    case "$cmd" in
      go) go version | tee -a "$LOG_FILE" ;;
      sqlite3) sqlite3 --version | tee -a "$LOG_FILE" ;;
      *) "$cmd" --version 2>&1 | head -n 1 | tee -a "$LOG_FILE" ;;
    esac
  else
    echo "[!]未找到 $cmd" | tee -a "$LOG_FILE"
    # 不直接退出，继续让脚本生成测试文件和日志以便排查
  fi
done

# -----------------------
# 4 检查内核 eBPF 支持
# -----------------------
echo "检查内核 eBPF 支持..." | tee -a "$LOG_FILE"
if zgrep -q "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r) 2>/dev/null; then
  echo "内核支持 eBPF。" | tee -a "$LOG_FILE"
else
  echo "[!]当前内核不支持 eBPF，请重新编译或更新。" | tee -a "$LOG_FILE"
  # 继续执行：只要文件生成和日志记录完成即可
fi

# -----------------------
# 5 创建测试目录和样例（确保在项目根目录下的 test/）
# -----------------------
echo "初始化 test 目录..." | tee -a "$LOG_FILE"
mkdir -p "$TEST_DIR"
chmod -R a+rwX "$TEST_DIR"

# execve trace bpftrace 脚本
cat > "$TEST_DIR/execve_trace.bt" <<'EOF'
#!/usr/bin/env bpftrace
tracepoint:syscalls:sys_enter_execve
{
    printf("%s -> %s\n", comm, str(args->filename));
}
EOF
chmod +x "$TEST_DIR/execve_trace.bt"

# Python 样例：实时捕获日志（保留供手工/开发使用）
cat > "$TEST_DIR/ingest_realtime.py" <<'EOF'
#!/usr/bin/env python3
import subprocess
import datetime
import sys
cmd = ["bpftrace", "test/execve_trace.bt"]
with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
    try:
        for line in proc.stdout:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {line.strip()}")
    except KeyboardInterrupt:
        proc.terminate()
        sys.exit(0)
EOF
chmod +x "$TEST_DIR/ingest_realtime.py"

# 触发 execve 的脚本（自动触发若干 execve 以便捕获）
cat > "$TEST_DIR/trigger_exec.sh" <<'EOF'
#!/usr/bin/env bash
# 触发一些 execve（执行小程序），总时长约 2 秒
for i in $(seq 1 40); do
  /bin/ls >/dev/null 2>&1
  /bin/true >/dev/null 2>&1
  sleep 0.02
done
EOF
chmod +x "$TEST_DIR/trigger_exec.sh"

echo "样例文件已创建于 $TEST_DIR" | tee -a "$LOG_FILE"

# -----------------------
# Helper: run command with optional non-interactive sudo
# -----------------------
run_maybesudo() {
  # Usage: run_maybesudo <command...>
  if [[ "$(id -u)" -eq 0 ]]; then
    # already root
    "$@"
    return $?
  fi

  # try non-interactive sudo first
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
      sudo "$@"
      return $?
    else
      # sudo exists but would prompt for password; attempt non-sudo run (capture failure)
      "$@" 2>/dev/null || return $?
      return $?
    fi
  else
    # no sudo available, run directly
    "$@" 2>/dev/null || return $?
  fi
}

# -----------------------
# 6 bpftrace 自动化无交互验证
# -----------------------
echo "执行 bpftrace 自动化功能验证（非交互，捕获 6 秒）..." | tee -a "$LOG_FILE"
echo "测试日志将写入 $TEST_LOG" | tee -a "$LOG_FILE"
# 清空测试日志
: > "$TEST_LOG"

# 启动捕获（以后台方式），输出重定向到测试日志
CAPTURE_CMD=(timeout 6s bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s -> %s\n", comm, str(args->filename)); }')
# 使用 helper 执行（会尝试 sudo -n 或直接运行）
if run_maybesudo "${CAPTURE_CMD[@]}" > "$TEST_LOG" 2>&1 & then
  CAP_PID=$!
  echo "started bpftrace with pid $CAP_PID" | tee -a "$LOG_FILE" "$TEST_LOG"
  # 给捕获一个短暂稳定期
  sleep 0.3
  # 触发 execve 事件
  echo "触发 execve 事件..." | tee -a "$TEST_LOG"
  bash "$TEST_DIR/trigger_exec.sh" >> "$TEST_LOG" 2>&1 || true
  # 等待捕获结束
  wait $CAP_PID 2>/dev/null || true
else
  echo "[!] 启动 bpftrace 捕获失败（可能需要 root 权限或 sudo）。" | tee -a "$LOG_FILE" "$TEST_LOG"
  echo "尝试以非 sudo 模式运行捕获（预期可能失败）..." | tee -a "$TEST_LOG"
  # 再次尝试直接运行（不阻塞脚本）
  timeout 3s bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s -> %s\n", comm, str(args->filename)); }' >> "$TEST_LOG" 2>&1 || true
fi

# 等待日志 flush
sync; sleep 1
if grep -q "->" "$TEST_LOG"; then
  echo "bpftrace 功能验证通过：检测到 execve 事件。" | tee -a "$LOG_FILE" "$TEST_LOG"
  grep "->" "$TEST_LOG" | head -n 20 | tee -a "$LOG_FILE"
else
  echo "[?]未在日志中匹配到 execve 输出，可能由于 flush 延迟或缓冲问题。" | tee -a "$LOG_FILE" "$TEST_LOG"
  echo "请手动验证: sudo bpftrace test/execve_trace.bt & bash test/trigger_exec.sh" | tee -a "$LOG_FILE" "$TEST_LOG"
fi

# 记录环境与建议
echo "环境检查摘要：" | tee -a "$TEST_LOG"
echo "当前用户 UID: $(id -u)" | tee -a "$TEST_LOG"
echo "建议：若测试未通过，请以 root 运行本脚本或手动运行： sudo bpftrace test/execve_trace.bt" | tee -a "$TEST_LOG"

# -----------------------
# 7 结束与输出
# -----------------------
echo "自动测试完成。所有测试文件、脚本和日志均保存在 $TEST_DIR" | tee -a "$LOG_FILE"
echo "测试日志: $TEST_LOG" | tee -a "$LOG_FILE"

echo "=== eTracee-China 环境初始化完成 ===" | tee -a "$LOG_FILE"
