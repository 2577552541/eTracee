#!/usr/bin/env bash
# 触发一些 execve（执行小程序），总时长约 2 秒
for i in $(seq 1 40); do
  /bin/ls >/dev/null 2>&1
  /bin/true >/dev/null 2>&1
  sleep 0.02
done
