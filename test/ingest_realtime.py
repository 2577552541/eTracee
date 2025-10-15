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
