#!/bin/bash

# eTracee 事件测试脚本
# 用于验证各种系统调用事件的捕获

echo "=== eTracee 事件测试脚本 ==="
echo "测试各种系统调用事件的捕获功能"
echo

# 测试1: 文件操作事件 (openat, unlink)
echo "1. 测试文件操作事件..."
touch /tmp/test_file_$$
echo "创建测试文件: /tmp/test_file_$$"
sleep 1
rm /tmp/test_file_$$
echo "删除测试文件"
sleep 1

# 测试2: 进程创建事件 (execve)
echo "2. 测试进程创建事件..."
/bin/ls /tmp > /dev/null
sleep 1

# 测试3: 网络事件 (socket)
echo "3. 测试网络事件..."
# 创建一个简单的socket连接
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.close()
" 2>/dev/null || echo "Python3不可用，跳过socket测试"
sleep 1

# 测试4: 内存操作 (通过简单的程序触发mmap)
echo "4. 测试内存操作事件..."
dd if=/dev/zero of=/tmp/mmap_test_$$ bs=1024 count=1 2>/dev/null
rm -f /tmp/mmap_test_$$
sleep 1

# 测试5: 权限相关操作
echo "5. 测试权限操作事件..."
# 尝试切换用户（通常会失败，但会触发setuid事件）
su -c "echo test" nobody 2>/dev/null || echo "权限测试完成（预期失败）"
sleep 1

echo "=== 测试完成 ==="
echo "请检查eTracee输出中是否包含以上操作的事件记录"