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
    // 原有事件类型 - 保持不变
    EVENT_EXECVE = 1,
    EVENT_OPENAT = 2,
    EVENT_CONNECT = 3,
    
    // 新增事件类型 - 扩展监控能力
    EVENT_MMAP = 4,           // 内存映射 - 检测代码注入
    EVENT_MPROTECT = 5,       // 内存保护修改 - 检测ROP/JOP
    EVENT_SETUID = 6,         // 用户ID修改 - 检测权限提升
    EVENT_SETGID = 7,         // 组ID修改
    EVENT_CLONE = 8,          // 进程创建 - 检测进程注入
    EVENT_PTRACE = 9,         // 进程调试 - 检测调试器附加
    EVENT_MOUNT = 10,         // 文件系统挂载
    EVENT_UNLINK = 11,        // 文件删除 - 检测日志清理
    EVENT_SOCKET = 12,        // Socket创建
    EVENT_BIND = 13,          // Socket绑定
    EVENT_LISTEN = 14,        // Socket监听
    EVENT_ACCEPT = 15,        // Socket接受连接
    EVENT_INIT_MODULE = 18,   // 内核模块加载 - 检测Rootkit
    EVENT_DELETE_MODULE = 19, // 内核模块卸载
    EVENT_PRCTL = 20,         // 进程控制
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
    
    // 新增字段 - 扩展事件信息
    union {
        struct {
            u64 addr;           // 内存地址 (mmap, mprotect)
            u64 len;            // 长度 (mmap, mprotect)
            u32 prot;           // 保护标志 (mmap, mprotect)
            u32 flags;          // 标志 (mmap)
        } mem;
        
        struct {
            u32 old_uid;        // 原用户ID (setuid)
            u32 new_uid;        // 新用户ID (setuid)
            u32 old_gid;        // 原组ID (setgid)
            u32 new_gid;        // 新组ID (setgid)
        } cred;
        
        struct {
            u32 target_pid;     // 目标进程ID (ptrace)
            u32 request;        // ptrace请求类型
            u64 addr;           // 地址参数
            u64 data;           // 数据参数
        } ptrace;
        
        struct {
            u32 family;         // 地址族 (socket)
            u32 type;           // socket类型
            u32 protocol;       // 协议
            u16 port;           // 端口 (bind, listen, accept)
        } net;
        
        struct {
            u32 option;         // prctl选项
            u64 arg2;           // 参数2
            u64 arg3;           // 参数3
        } prctl;
        
        u64 raw_args[4];        // 原始参数，用于未特殊处理的事件
    } data;
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

/* 捕获 mmap 系统调用 - 检测内存映射 */
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_MMAP;
    e->syscall_nr = ctx->id;
    
    // 提取 mmap 参数
    e->data.mem.addr = ctx->args[0];    // void *addr
    e->data.mem.len = ctx->args[1];     // size_t length
    e->data.mem.prot = ctx->args[2];    // int prot
    e->data.mem.flags = ctx->args[3];   // int flags

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 mprotect 系统调用 - 检测内存保护修改 */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_MPROTECT;
    e->syscall_nr = ctx->id;
    
    // 提取 mprotect 参数
    e->data.mem.addr = ctx->args[0];    // void *addr
    e->data.mem.len = ctx->args[1];     // size_t len
    e->data.mem.prot = ctx->args[2];    // int prot

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 setuid 系统调用 - 检测权限提升 */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_SETUID;
    e->syscall_nr = ctx->id;
    
    // 记录 UID 变化
    e->data.cred.old_uid = e->uid;      // 当前 UID
    e->data.cred.new_uid = ctx->args[0]; // 新 UID

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 setgid 系统调用 - 检测权限提升 */
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_SETGID;
    e->syscall_nr = ctx->id;
    
    // 记录 GID 变化
    e->data.cred.old_gid = e->gid;      // 当前 GID
    e->data.cred.new_gid = ctx->args[0]; // 新 GID

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 ptrace 系统调用 - 检测进程调试 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_PTRACE;
    e->syscall_nr = ctx->id;
    
    // 提取 ptrace 参数
    e->data.ptrace.request = ctx->args[0];    // long request
    e->data.ptrace.target_pid = ctx->args[1]; // pid_t pid
    e->data.ptrace.addr = ctx->args[2];       // void *addr
    e->data.ptrace.data = ctx->args[3];       // void *data

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 unlink 系统调用 - 检测文件删除 */
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink_enter(struct trace_event_raw_sys_enter *ctx)
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
    
    e->event_type = EVENT_UNLINK;
    e->syscall_nr = ctx->id;

    /* 读取文件名参数 */
    filename_ptr = (void *)ctx->args[0];
    if (filename_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 socket 系统调用 - 检测网络socket创建 */
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_SOCKET;
    e->syscall_nr = ctx->id;
    
    // 提取 socket 参数
    e->data.net.family = ctx->args[0];   // int family
    e->data.net.type = ctx->args[1];     // int type
    e->data.net.protocol = ctx->args[2]; // int protocol

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 prctl 系统调用 - 检测进程控制 */
SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);
    
    e->event_type = EVENT_PRCTL;
    e->syscall_nr = ctx->id;
    
    // 提取 prctl 参数
    e->data.prctl.option = ctx->args[0]; // int option
    e->data.prctl.arg2 = ctx->args[1];   // unsigned long arg2
    e->data.prctl.arg3 = ctx->args[2];   // unsigned long arg3

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";