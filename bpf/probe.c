// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 eTracee Project */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

/* 事件类型定义 */
enum event_type {
    EVENT_EXECVE = 1,
    EVENT_OPENAT = 2,
    EVENT_CONNECT = 3,
};

/* 传输给用户态的事件结构 */
struct event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 event_type;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    u32 syscall_nr;
    s32 ret_code;
};

/* Ring Buffer Map 定义 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} rb SEC(".maps");

/* 获取当前任务信息的辅助函数 */
static __always_inline void fill_task_info(struct event *e, struct task_struct *task)
{
    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* 捕获 execve 系统调用 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;
    void *filename_ptr;

    /* 分配 ring buffer 空间 */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* 初始化事件结构 */
    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_EXECVE;
    e->syscall_nr = ctx->id;

    /* 读取文件名参数 */
    filename_ptr = (void *)ctx->args[0];
    if (filename_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    }

    /* 提交事件到 ring buffer */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 execve 系统调用返回 */
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct event *e;
    struct task_struct *task;

    /* 只记录成功的 execve 调用 */
    if (ctx->ret < 0)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_EXECVE;
    e->syscall_nr = ctx->id;
    e->ret_code = ctx->ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 openat 系统调用 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;
    void *filename_ptr;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_OPENAT;
    e->syscall_nr = ctx->id;

    /* 读取文件名参数 (第二个参数) */
    filename_ptr = (void *)ctx->args[1];
    if (filename_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 connect 系统调用 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_CONNECT;
    e->syscall_nr = ctx->id;

    /* 对于 connect，我们主要关注进程信息 */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";