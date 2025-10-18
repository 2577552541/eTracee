package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	jsoniter "github.com/json-iterator/go"
)

// Event 表示从eBPF程序接收到的事件 - 必须与eBPF中的struct event完全匹配
type Event struct {
	Timestamp uint64    `json:"timestamp"`
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	EventType uint32    `json:"event_type"`
	Comm      [16]byte  `json:"-"`
	Filename  [256]byte `json:"-"`
	SyscallNr uint32    `json:"syscall_nr"`
	RetCode   int32     `json:"ret_code"`
	
	// 扩展数据字段 - 与 eBPF 中的 union 对应
	Data EventData `json:"data"`
}

// EventData 对应 eBPF 中的 union data - 使用原始字节数组来匹配union
type EventData struct {
	// 使用32字节的原始数据来匹配eBPF中的union (4 * uint64 = 32字节)
	RawData [4]uint64 `json:"-"`
}

// EventOutput 用于JSON输出的结构体
type EventOutput struct {
	Timestamp   uint64    `json:"timestamp"`
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	UID         uint32    `json:"uid"`
	GID         uint32    `json:"gid"`
	EventType   uint32    `json:"event_type"`
	SyscallNr   uint32    `json:"syscall_nr"`
	RetCode     int32     `json:"ret_code"`
	Comm        string    `json:"comm"`
	Filename    string    `json:"filename"`
	EventName   string    `json:"event_name"`
	TimeStr     string    `json:"time_str"`
	
	// 解析后的数据字段
	Data        map[string]interface{} `json:"data"`
}

// 将字节数组转换为字符串
func bytesToString(b []byte) string {
	n := 0
	for i, v := range b {
		if v == 0 {
			n = i
			break
		}
	}
	if n == 0 && len(b) > 0 && b[0] != 0 {
		n = len(b)
	}
	return string(b[:n])
}

// 获取事件名称
func getEventName(eventType uint32) string {
	switch eventType {
	// 原有事件类型
	case 1: // EVENT_EXECVE
		return "execve"
	case 2: // EVENT_OPENAT
		return "openat"
	case 3: // EVENT_CONNECT
		return "connect"
	
	// 新增事件类型
	case 4: // EVENT_MMAP
		return "mmap"
	case 5: // EVENT_MPROTECT
		return "mprotect"
	case 6: // EVENT_SETUID
		return "setuid"
	case 7: // EVENT_SETGID
		return "setgid"
	case 8: // EVENT_CLONE
		return "clone"
	case 9: // EVENT_PTRACE
		return "ptrace"
	case 10: // EVENT_MOUNT
		return "mount"
	case 11: // EVENT_UNLINK
		return "unlink"
	case 12: // EVENT_SOCKET
		return "socket"
	case 13: // EVENT_BIND
		return "bind"
	case 14: // EVENT_LISTEN
		return "listen"
	case 15: // EVENT_ACCEPT
		return "accept"
	case 18: // EVENT_INIT_MODULE
		return "init_module"
	case 19: // EVENT_DELETE_MODULE
		return "delete_module"
	case 20: // EVENT_PRCTL
		return "prctl"
	default:
		return fmt.Sprintf("event_%d", eventType)
	}
}

// 格式化时间戳
func formatTimestamp(timestamp uint64) string {
	// bpf_ktime_get_ns() 返回的是系统启动后的纳秒数，需要转换为实际时间
	now := time.Now()
	
	// 更准确的方法：使用当前时间减去时间差
	uptime := getSystemUptime()
	if uptime > 0 {
		// 系统启动时间 = 当前时间 - 系统运行时间
		systemBootTime := now.Add(-time.Duration(uptime) * time.Second)
		// 事件时间 = 系统启动时间 + eBPF时间戳（纳秒）
		eventTime := systemBootTime.Add(time.Duration(timestamp))
		return eventTime.Format("2006-01-02 15:04:05.000000")
	} else {
		// 如果无法获取系统运行时间，使用当前时间
		return now.Format("2006-01-02 15:04:05.000000")
	}
}

// 获取系统运行时间（秒）
// parseEventData 根据事件类型解析union数据
func parseEventData(eventType uint32, rawData [4]uint64) map[string]interface{} {
	data := make(map[string]interface{})
	
	switch eventType {
	case 4, 5: // EVENT_MMAP, EVENT_MPROTECT
		data["addr"] = rawData[0]
		data["len"] = rawData[1]
		data["prot"] = uint32(rawData[2] & 0xFFFFFFFF)
		data["flags"] = uint32((rawData[2] >> 32) & 0xFFFFFFFF)
		
	case 6, 7: // EVENT_SETUID, EVENT_SETGID
		data["old_uid"] = uint32(rawData[0] & 0xFFFFFFFF)
		data["new_uid"] = uint32((rawData[0] >> 32) & 0xFFFFFFFF)
		data["old_gid"] = uint32(rawData[1] & 0xFFFFFFFF)
		data["new_gid"] = uint32((rawData[1] >> 32) & 0xFFFFFFFF)
		
	case 9: // EVENT_PTRACE
		data["target_pid"] = uint32(rawData[0] & 0xFFFFFFFF)
		data["request"] = uint32((rawData[0] >> 32) & 0xFFFFFFFF)
		data["addr"] = rawData[1]
		data["data"] = rawData[2]
		
	case 12: // EVENT_SOCKET
		data["family"] = uint32(rawData[0] & 0xFFFFFFFF)
		data["type"] = uint32((rawData[0] >> 32) & 0xFFFFFFFF)
		data["protocol"] = uint32(rawData[1] & 0xFFFFFFFF)
		data["port"] = uint16((rawData[1] >> 32) & 0xFFFF)
		
	case 20: // EVENT_PRCTL
		data["option"] = uint32(rawData[0] & 0xFFFFFFFF)
		data["arg2"] = rawData[1]
		data["arg3"] = rawData[2]
		
	default:
		// 对于其他事件类型，返回原始参数
		data["raw_args"] = []uint64{rawData[0], rawData[1], rawData[2], rawData[3]}
	}
	
	return data
}
func getSystemUptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	
	uptimeStr := strings.Fields(string(data))[0]
	uptime, err := strconv.ParseFloat(uptimeStr, 64)
	if err != nil {
		return 0
	}
	
	return int64(uptime)
}

func main() {
	// 移除内存限制 (仅在 Linux 上需要)
	if err := rlimit.RemoveMemlock(); err != nil {
		// 在 Windows 上这个操作会失败，但不影响程序运行
		log.Printf("警告: 移除内存限制失败 (可能运行在非 Linux 系统): %v", err)
		log.Println("注意: 在 Windows 系统上，eBPF 功能不可用，程序将以兼容模式运行")
	}

	// 加载eBPF程序 - 使用相对于可执行文件的路径
	probeFile := "../bpf/probe.o"
	// 如果从项目根目录运行，使用这个路径
	if _, err := os.Stat("bpf/probe.o"); err == nil {
		probeFile = "bpf/probe.o"
	}
	
	spec, err := ebpf.LoadCollectionSpec(probeFile)
	if err != nil {
		log.Fatal("加载eBPF程序规范失败:", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal("创建eBPF集合失败:", err)
	}
	defer coll.Close()

	// 获取Ring Buffer映射
	rb, err := ringbuf.NewReader(coll.Maps["rb"])
	if err != nil {
		log.Fatal("创建Ring Buffer读取器失败:", err)
	}
	defer rb.Close()

	// 附加tracepoint程序
	programs := []struct {
		name      string
		program   *ebpf.Program
		group     string
		name_tp   string
	}{
		// 原有程序
		{"trace_execve_enter", coll.Programs["trace_execve_enter"], "syscalls", "sys_enter_execve"},
		{"trace_execve_exit", coll.Programs["trace_execve_exit"], "syscalls", "sys_exit_execve"},
		{"trace_openat_enter", coll.Programs["trace_openat_enter"], "syscalls", "sys_enter_openat"},
		{"trace_connect_enter", coll.Programs["trace_connect_enter"], "syscalls", "sys_enter_connect"},
		
		// 新增程序
		{"trace_mmap_enter", coll.Programs["trace_mmap_enter"], "syscalls", "sys_enter_mmap"},
		{"trace_mprotect_enter", coll.Programs["trace_mprotect_enter"], "syscalls", "sys_enter_mprotect"},
		{"trace_setuid_enter", coll.Programs["trace_setuid_enter"], "syscalls", "sys_enter_setuid"},
		{"trace_setgid_enter", coll.Programs["trace_setgid_enter"], "syscalls", "sys_enter_setgid"},
		{"trace_ptrace_enter", coll.Programs["trace_ptrace_enter"], "syscalls", "sys_enter_ptrace"},
		{"trace_unlink_enter", coll.Programs["trace_unlink_enter"], "syscalls", "sys_enter_unlink"},
		{"trace_socket_enter", coll.Programs["trace_socket_enter"], "syscalls", "sys_enter_socket"},
		{"trace_prctl_enter", coll.Programs["trace_prctl_enter"], "syscalls", "sys_enter_prctl"},
	}

	var links []link.Link
	for _, prog := range programs {
		if prog.program == nil {
			log.Printf("警告: 程序 %s 不存在", prog.name)
			continue
		}

		l, err := link.Tracepoint(prog.group, prog.name_tp, prog.program, nil)
		if err != nil {
			log.Printf("附加tracepoint %s/%s 失败: %v", prog.group, prog.name_tp, err)
			continue
		}
		links = append(links, l)
		log.Printf("成功附加tracepoint: %s/%s", prog.group, prog.name_tp)
	}

	// 确保在退出时清理资源
	defer func() {
		log.Println("执行最终清理...")
		// 这里只是备用清理，主要清理在信号处理中完成
		for _, l := range links {
			if l != nil {
				l.Close()
			}
		}
		if rb != nil {
			rb.Close()
		}
	}()

	log.Println("eTracee eBPF监控程序已启动，开始监控系统调用...")
	log.Println("按 Ctrl+C 退出程序")

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	// 启动信号处理goroutine
	go func() {
		<-c
		log.Println("接收到退出信号，正在清理资源...")
		
		// 首先关闭所有tracepoint链接，停止事件采集
		for _, l := range links {
			l.Close()
		}
		log.Println("已停止eBPF事件采集")
		
		// 然后关闭Ring Buffer
		rb.Close()
		log.Println("已关闭Ring Buffer")
		
		// 最后取消context
		cancel()
	}()

	// JSON编码器
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	// 读取事件循环
	for {
		select {
		case <-ctx.Done():
			log.Println("程序退出")
			return
		default:
			record, err := rb.Read()
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					log.Println("Ring Buffer已关闭，停止事件处理")
					return
				}
				log.Printf("读取Ring Buffer失败: %v", err)
				continue
			}

			if len(record.RawSample) < int(unsafe.Sizeof(Event{})) {
				log.Printf("事件数据长度不足: 期望 %d，实际 %d", unsafe.Sizeof(Event{}), len(record.RawSample))
				continue
			}

			// 解析事件数据
			var event Event
			data := record.RawSample

			// 使用binary.Read解析结构体
			reader := bytes.NewReader(data)
			if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
				log.Printf("解析事件数据失败: %v", err)
				continue
			}

			// 过滤掉程序自身的事件，避免无限循环
			if event.PID == uint32(os.Getpid()) {
				continue
			}

			// 创建输出结构体
			output := EventOutput{
				Timestamp: event.Timestamp,
				PID:       event.PID,
				PPID:      event.PPID,
				UID:       event.UID,
				GID:       event.GID,
				EventType: event.EventType,
				SyscallNr: event.SyscallNr,
				RetCode:   event.RetCode,
				Comm:      bytesToString(event.Comm[:]),
				Filename:  bytesToString(event.Filename[:]),
				EventName: getEventName(event.EventType),
				TimeStr:   formatTimestamp(event.Timestamp),
				Data:      parseEventData(event.EventType, event.Data.RawData), // 解析扩展数据
			}

			// 输出JSON格式的事件
			jsonData, err := json.Marshal(output)
			if err != nil {
				log.Printf("JSON序列化失败: %v", err)
				continue
			}

			fmt.Println(string(jsonData))
		}
	}
}