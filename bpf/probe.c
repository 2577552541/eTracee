// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 eTracee Project */

// eBPF内核程序头文件包含
#include "vmlinux.h"          // 内核数据结构定义
#include <bpf/bpf_helpers.h>   // eBPF辅助函数
#include <bpf/bpf_tracing.h>   // eBPF跟踪相关函数
#include <bpf/bpf_core_read.h> // CO-RE (Compile Once, Run Everywhere) 读取函数

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

/* 事件类型定义 */
enum event_type {
    // 原有事件类型 - 保持不变
    EVENT_EXECVE = 1,         // 进程执行事件 - 监控程序启动
    EVENT_OPENAT = 2,         // 文件打开事件 - 监控文件访问
    EVENT_CONNECT = 3,        // 网络连接事件 - 监控网络通信
    
    // 新增事件类型 - 扩展监控能力
    EVENT_MMAP = 4,           // 内存映射事件 - 检测代码注入
    EVENT_MPROTECT = 5,       // 内存保护修改事件 - 检测ROP/JOP攻击
    EVENT_SETUID = 6,         // 用户ID修改事件 - 检测权限提升
    EVENT_SETGID = 7,         // 组ID修改事件 - 检测权限提升
    EVENT_CLONE = 8,          // 进程创建事件 - 检测进程注入
    EVENT_PTRACE = 9,         // 进程调试事件 - 检测调试器附加
    EVENT_MOUNT = 10,         // 文件系统挂载事件 - 检测恶意挂载
    EVENT_UNLINK = 11,        // 文件删除事件 - 检测日志清理
    EVENT_SOCKET = 12,        // Socket创建事件 - 检测网络活动
    EVENT_BIND = 13,          // Socket绑定事件 - 检测端口监听
    EVENT_LISTEN = 14,        // Socket监听事件 - 检测服务启动
    EVENT_ACCEPT = 15,        // Socket接受连接事件 - 检测连接建立
    EVENT_INIT_MODULE = 18,   // 内核模块加载事件 - 检测Rootkit
    EVENT_DELETE_MODULE = 19, // 内核模块卸载事件 - 检测模块操作
    EVENT_PRCTL = 20,         // 进程控制事件 - 检测进程行为修改
};

/* 传输给用户态的事件结构 - 定义内核态和用户态之间的数据交换格式 */
struct event {
    u64 timestamp;                    // 事件发生时间戳（纳秒精度）
    u32 pid;                         // 触发事件的进程ID
    u32 ppid;                        // 父进程ID
    u32 uid;                         // 用户ID（实际用户ID）
    u32 gid;                         // 组ID（实际组ID）
    u32 event_type;                  // 事件类型（对应enum event_type）
    char comm[TASK_COMM_LEN];        // 进程命令名（最多15字符）
    char filename[MAX_FILENAME_LEN]; // 相关文件名或路径（最多255字符）
    u32 syscall_nr;                  // 系统调用号
    s32 ret_code;                    // 系统调用返回值
    
    // 联合体 - 根据不同事件类型存储特定的扩展信息
    union {
        // 内存操作相关数据（用于mmap、mprotect事件）
        struct {
            u64 addr;           // 内存起始地址
            u64 len;            // 内存区域长度
            u32 prot;           // 内存保护标志（PROT_READ/PROT_WRITE/PROT_EXEC等）
            u32 flags;          // 映射标志（MAP_PRIVATE/MAP_SHARED等）
        } mem;
        
        // 凭证变更相关数据（用于setuid、setgid事件）
        struct {
            u32 old_uid;        // 变更前的用户ID
            u32 new_uid;        // 变更后的用户ID
            u32 old_gid;        // 变更前的组ID
            u32 new_gid;        // 变更后的组ID
        } cred;
        
        // 进程调试相关数据（用于ptrace事件）
        struct {
            u32 target_pid;     // 被调试的目标进程ID
            u32 request;        // ptrace请求类型（PTRACE_ATTACH等）
            u64 addr;           // 内存地址参数
            u64 data;           // 数据参数
        } ptrace;
        
        // 网络相关数据（用于socket、bind、connect等事件）
        struct {
            u32 family;         // 协议族（AF_INET、AF_INET6等）
            u32 type;           // socket类型（SOCK_STREAM、SOCK_DGRAM等）
            u32 protocol;       // 协议类型（IPPROTO_TCP、IPPROTO_UDP等）
            u16 port;           // 端口号（网络字节序）
        } net;
        
        // 进程控制相关数据（用于prctl事件）
        struct {
            u32 option;         // prctl操作选项（PR_SET_NAME等）
            u64 arg2;           // 第二个参数
            u64 arg3;           // 第三个参数
        } prctl;
        
        u64 raw_args[4];        // 原始系统调用参数数组（用于未特殊处理的事件）
    } data;
};

/* Ring Buffer Map 定义 - 用于高效的内核态到用户态数据传输 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);  // 使用Ring Buffer类型的BPF映射
    __uint(max_entries, 256 * 1024);     // 最大256KB缓冲区大小
} rb SEC(".maps");

/* 获取当前任务信息的辅助函数 - 填充事件通用数据 */
static __always_inline void fill_task_info(struct event *e, struct task_struct *task)
{
    e->timestamp = bpf_ktime_get_ns();                    // 获取当前时间戳（纳秒精度）
    e->pid = bpf_get_current_pid_tgid() >> 32;           // 获取当前进程ID（高32位）
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);    // 通过CO-RE读取父进程ID
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;     // 获取用户ID（低32位）
    e->gid = bpf_get_current_uid_gid() >> 32;            // 获取组ID（高32位）
    bpf_get_current_comm(&e->comm, sizeof(e->comm));     // 获取进程命令名
}

/* 捕获 execve 系统调用 - 监控进程执行事件 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;
    void *filename_ptr;

    /* 分配 ring buffer 空间 - 从Ring Buffer预留空间用于存储事件数据 */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;  // 预留失败，直接返回

    /* 初始化事件结构 - 清零所有字段 */
    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_EXECVE;  // 设置事件类型为进程执行
    e->syscall_nr = ctx->id;       // 记录系统调用号

    /* 读取文件名参数 - 从用户空间读取要执行的文件名 */
    filename_ptr = (void *)ctx->args[0];
    if (filename_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    }

    /* 提交事件到 ring buffer - 将事件数据发送到用户态 */
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

/* 捕获 openat 系统调用 - 监控文件打开事件 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;
    void *filename_ptr;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_OPENAT;  // 设置事件类型为文件打开
    e->syscall_nr = ctx->id;       // 记录系统调用号

    /* 读取文件名参数 (第二个参数) - 从用户空间读取要打开的文件名 */
    filename_ptr = (void *)ctx->args[1];
    if (filename_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    }

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 connect 系统调用 - 监控网络连接事件 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_CONNECT;  // 设置事件类型为网络连接
    e->syscall_nr = ctx->id;        // 记录系统调用号

    /* 对于 connect，我们主要关注进程信息 - 可扩展提取socket地址信息 */
    bpf_ringbuf_submit(e, 0);  // 提交事件到Ring Buffer
    return 0;
}

/* 捕获 mmap 系统调用 - 检测内存映射（可能的代码注入检测） */
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_MMAP;   // 设置事件类型为内存映射
    e->syscall_nr = ctx->id;      // 记录系统调用号
    
    // 提取mmap系统调用的关键参数
    e->data.mem.addr = ctx->args[0];    // void *addr - 映射地址（可为NULL让内核选择）
    e->data.mem.len = ctx->args[1];     // size_t length - 映射长度
    e->data.mem.prot = ctx->args[2];    // int prot - 内存保护标志（读/写/执行权限）
    e->data.mem.flags = ctx->args[3];   // int flags - 映射标志（私有/共享等）

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 mprotect 系统调用 - 检测内存保护修改（ROP/JOP攻击检测） */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_MPROTECT;  // 设置事件类型为内存保护修改
    e->syscall_nr = ctx->id;         // 记录系统调用号
    
    // 提取mprotect系统调用的关键参数
    e->data.mem.addr = ctx->args[0];    // void *addr - 要修改保护的内存地址
    e->data.mem.len = ctx->args[1];     // size_t len - 内存区域长度
    e->data.mem.prot = ctx->args[2];    // int prot - 新的保护标志（重点关注执行权限变化）

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 setuid 系统调用 - 检测权限提升（特权升级检测） */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_SETUID;  // 设置事件类型为用户ID修改
    e->syscall_nr = ctx->id;       // 记录系统调用号
    
    // 记录UID变化信息 - 用于检测权限提升攻击
    e->data.cred.old_uid = e->uid;       // 当前UID（变更前）
    e->data.cred.new_uid = ctx->args[0]; // 新UID（变更后）

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 setgid 系统调用 - 检测权限提升（组权限升级检测） */
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_SETGID;  // 设置事件类型为组ID修改
    e->syscall_nr = ctx->id;       // 记录系统调用号
    
    // 记录GID变化信息 - 用于检测组权限提升攻击
    e->data.cred.old_gid = e->gid;       // 当前GID（变更前）
    e->data.cred.new_gid = ctx->args[0]; // 新GID（变更后）

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 ptrace 系统调用 - 检测进程调试（调试器附加和进程注入检测） */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_PTRACE;  // 设置事件类型为进程调试
    e->syscall_nr = ctx->id;       // 记录系统调用号
    
    // 提取ptrace系统调用的关键参数
    e->data.ptrace.request = ctx->args[0];    // long request - ptrace操作类型（ATTACH/DETACH等）
    e->data.ptrace.target_pid = ctx->args[1]; // pid_t pid - 目标进程ID
    e->data.ptrace.addr = ctx->args[2];       // void *addr - 内存地址参数
    e->data.ptrace.data = ctx->args[3];       // void *data - 数据参数

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 unlink 系统调用 - 检测文件删除（日志清理和痕迹擦除检测） */
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;
    void *filename_ptr;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_UNLINK;  // 设置事件类型为文件删除
    e->syscall_nr = ctx->id;       // 记录系统调用号

    /* 读取要删除的文件名参数 - 用于检测敏感文件删除 */
    filename_ptr = (void *)ctx->args[0];
    if (filename_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    }

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 socket 系统调用 - 检测网络socket创建（网络活动监控） */
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_SOCKET;  // 设置事件类型为Socket创建
    e->syscall_nr = ctx->id;       // 记录系统调用号
    
    // 提取socket系统调用的关键参数
    e->data.net.family = ctx->args[0];   // int family - 协议族（AF_INET/AF_INET6等）
    e->data.net.type = ctx->args[1];     // int type - socket类型（STREAM/DGRAM等）
    e->data.net.protocol = ctx->args[2]; // int protocol - 协议类型（TCP/UDP等）

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 捕获 prctl 系统调用 - 检测进程控制（进程行为修改检测） */
SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // 从Ring Buffer预留空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    task = (struct task_struct *)bpf_get_current_task();
    fill_task_info(e, task);  // 填充事件基本信息
    
    e->event_type = EVENT_PRCTL;  // 设置事件类型为进程控制
    e->syscall_nr = ctx->id;      // 记录系统调用号
    
    // 提取prctl系统调用的关键参数
    e->data.prctl.option = ctx->args[0]; // int option - prctl操作选项（PR_SET_NAME等）
    e->data.prctl.arg2 = ctx->args[1];   // unsigned long arg2 - 第二个参数
    e->data.prctl.arg3 = ctx->args[2];   // unsigned long arg3 - 第三个参数

    // 提交事件到Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";