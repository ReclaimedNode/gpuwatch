#!/usr/bin/env python3
"""
gpuwatch agent - nvtop-style live GPU stats over HTTP, for NVIDIA and Apple Silicon.

  NVIDIA (Linux):        nvidia-smi
  Apple Silicon (macOS): ioreg (utilization + GPU memory in use), sysctl (wired limit),
                         top (processes, CPU, RAM), powermetrics (clock/power, root only)

Endpoints
  /                      dashboard (dashboard.html next to this file)
  /stats                 current snapshot (JSON)
  /history               recent samples per GPU (JSON, ages in seconds)
  /config        GET     saved host list the dashboard shows
                 POST    {"hosts": [...]} to save it
  /proxy/<host:port>/stats|history
                         fetch another agent server-side (only hosts in the saved list),
                         so the dashboard works behind HTTPS / a reverse proxy

Standard library only. Python 3.8+.
"""
import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import random
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.1.0"
HERE = os.path.dirname(os.path.abspath(__file__))
MiB = 1024 ** 2
GiB = 1024 ** 3
DEFAULT_PORT = 9180
HISTORY_SECONDS = 900
PINS_JSON = "[]"          # replaced per machine by the hub with that machine's pinned services


# ----------------------------------------------------------------------------- helpers

def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=timeout)
        return r.stdout or ""
    except Exception:
        return ""


def num(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s or s.startswith("[") or s.upper() in ("N/A", "NOT SUPPORTED"):
        return None
    try:
        return float(s)
    except ValueError:
        return None


def parse_size(s):
    """'180G', '5243M+', '12K-', '980B' -> bytes"""
    m = re.match(r"\s*([\d.]+)([BKMGT]?)", s or "")
    if not m:
        return None
    mult = {"": 1, "B": 1, "K": 1024, "M": MiB, "G": GiB, "T": 1024 ** 4}[m.group(2)]
    return int(float(m.group(1)) * mult)


_SECRET_RE = re.compile(
    r"(?i)((?:--?|\b)(?:api[-_]?key|apikey|access[-_]?token|auth[-_]?token|token|secret|password|passwd|pwd|"
    r"hf[-_]?token|bearer|credentials?)(?:\s*[=:]\s*|\s+))(\"[^\"]*\"|'[^']*'|\S+)")
_URL_CRED_RE = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@")


def redact(cmd):
    """Hide values of secret-looking flags/env assignments and URL credentials in a command line."""
    if not cmd:
        return cmd
    cmd = _SECRET_RE.sub(lambda m: m.group(1) + "***", str(cmd))
    return _URL_CRED_RE.sub(lambda m: m.group(1) + "***@", cmd)


def norm_host(h, default_port=DEFAULT_PORT):
    h = (h or "").strip()
    for pre in ("http://", "https://"):
        if h.startswith(pre):
            h = h[len(pre):]
    h = h.split("/")[0]
    if not h:
        return ""
    if h.startswith("["):              # [ipv6]:port
        return h if "]:" in h else h + ":%d" % default_port
    if h.count(":") == 1:
        return h
    return h + ":%d" % default_port


# ----------------------------------------------------------------------------- Linux host

class LinuxHost:
    def __init__(self):
        self.prev_cpu = None
        self.prev_proc = {}
        self.clk = os.sysconf("SC_CLK_TCK")

    def cpu_pct(self):
        try:
            with open("/proc/stat") as f:
                vals = [int(x) for x in f.readline().split()[1:]]
        except Exception:
            return None
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals[:8])
        pct = None
        if self.prev_cpu:
            dt, di = total - self.prev_cpu[0], idle - self.prev_cpu[1]
            if dt > 0:
                pct = 100.0 * (dt - di) / dt
        self.prev_cpu = (total, idle)
        return pct

    def mem(self):
        info = {}
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    k, v = line.split(":", 1)
                    info[k] = int(v.split()[0]) * 1024
        except Exception:
            return None, None
        total = info.get("MemTotal", 0)
        return total - info.get("MemAvailable", 0), total

    def proc_info(self, pid):
        d = {"user": "?", "cpu": None, "host_mem": None, "command": "?"}
        try:
            import pwd
            st = os.stat("/proc/%d" % pid)
            try:
                d["user"] = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                d["user"] = str(st.st_uid)
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            fields = s[s.rfind(")") + 2:].split()
            ticks = int(fields[11]) + int(fields[12])
            now = time.time()
            prev = self.prev_proc.get(pid)
            if prev:
                d["cpu"] = 100.0 * (ticks - prev[0]) / self.clk / max(now - prev[1], 1e-3)
            self.prev_proc[pid] = (ticks, now)
            with open("/proc/%d/status" % pid) as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        d["host_mem"] = int(line.split()[1]) * 1024
                        break
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
            if not cmd:
                with open("/proc/%d/comm" % pid) as f:
                    cmd = f.read().strip()
            d["command"] = redact(cmd)[:500]
        except Exception:
            pass
        return d

    def prune(self, keep):
        for pid in list(self.prev_proc):
            if pid not in keep:
                del self.prev_proc[pid]

    def host_stats(self):
        used, total = self.mem()
        return {"cpu": self.cpu_pct(), "mem_used": used, "mem_total": total}


# ----------------------------------------------------------------------------- NVIDIA

class Nvidia:
    FIELDS = ("index,name,uuid,utilization.gpu,memory.used,memory.total,temperature.gpu,"
              "power.draw,power.limit,fan.speed,clocks.gr,clocks.mem,"
              "pcie.link.gen.current,pcie.link.width.current")

    def __init__(self):
        self.host = LinuxHost()
        self.pcie = {}
        threading.Thread(target=self._pcie_loop, daemon=True).start()

    def _pcie_loop(self):
        """PCIe RX/TX MB/s per GPU (nvidia-smi dmon samples for ~1 s)."""
        fails = 0
        while fails < 5:
            out = run(["nvidia-smi", "dmon", "-s", "t", "-c", "1"], timeout=15)
            d = {}
            for l in out.splitlines():
                parts = l.split()
                if not parts or l.lstrip().startswith("#") or not parts[0].isdigit() or len(parts) < 3:
                    continue
                d[int(parts[0])] = (num(parts[1]), num(parts[2]))
            if d:
                fails = 0
                self.pcie = d
            else:
                fails += 1
            time.sleep(1)

    def collect(self):
        out = run(["nvidia-smi", "--query-gpu=" + self.FIELDS, "--format=csv,noheader,nounits"])
        gpus, by_uuid = [], {}
        for line in out.strip().splitlines():
            p = [x.strip() for x in line.split(",")]
            if len(p) < 14:
                continue
            try:
                idx = int(p[0])
            except ValueError:
                continue
            mu, mt = num(p[4]), num(p[5])
            gpus.append({
                "index": idx, "name": p[1],
                "util": num(p[3]),
                "mem_used": mu * MiB if mu is not None else None,
                "mem_total": mt * MiB if mt is not None else None,
                "temp": num(p[6]), "power": num(p[7]), "power_limit": num(p[8]),
                "fan": num(p[9]), "clock_gr": num(p[10]), "clock_mem": num(p[11]),
                "bus": ("PCIe GEN %s@%sx" % (p[12], p[13])) if num(p[12]) else None,
                "pcie_rx": (self.pcie.get(idx) or (None, None))[0],
                "pcie_tx": (self.pcie.get(idx) or (None, None))[1],
            })
            by_uuid[p[2]] = idx

        procs, seen = [], set()
        out = run(["nvidia-smi", "--query-compute-apps=pid,gpu_uuid,used_memory",
                   "--format=csv,noheader,nounits"])
        for line in out.strip().splitlines():
            p = [x.strip() for x in line.split(",")]
            if len(p) < 3:
                continue
            try:
                pid = int(p[0])
            except ValueError:
                continue
            seen.add(pid)
            used = num(p[2])
            info = self.host.proc_info(pid)
            procs.append(dict(info, pid=pid, dev=by_uuid.get(p[1]), type="Compute",
                              gpu_mem=used * MiB if used is not None else None))
        self.host.prune(seen)
        procs.sort(key=lambda x: (x["dev"] if x["dev"] is not None else 99, -(x["gpu_mem"] or 0)))
        return {"kind": "nvidia", "host": self.host.host_stats(), "gpus": gpus, "procs": procs}


# ----------------------------------------------------------------------------- Apple Silicon

class Apple:
    def __init__(self, nprocs=10):
        self.nprocs = nprocs
        self.memsize = int(num(run(["sysctl", "-n", "hw.memsize"])) or 0)
        self.chip = run(["sysctl", "-n", "machdep.cpu.brand_string"]).strip() or "Apple Silicon"
        self.lock = threading.Lock()
        self.pm = {}
        self.top = {"procs": [], "cpu": None, "mem_used": None}
        threading.Thread(target=self._top_loop, daemon=True).start()
        # powermetrics needs root: run directly as root, or via passwordless sudo if allowed
        self.pm_cmd = None
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.pm_cmd = ["powermetrics"]
        elif shutil.which("sudo"):
            self.pm_cmd = ["sudo", "-n", "/usr/bin/powermetrics"]
        if self.pm_cmd:
            threading.Thread(target=self._pm_loop, daemon=True).start()

    def wired_limit(self):
        v = num(run(["sysctl", "-n", "iogpu.wired_limit_mb"]))
        if v and v > 0:
            return int(v * MiB), False
        # macOS default when unset: about 2/3 of RAM up to 36 GB, about 3/4 above that
        frac = 0.75 if self.memsize > 36 * GiB else 2.0 / 3.0
        return int(self.memsize * frac), True

    def _top_loop(self):
        while True:
            out = run(["top", "-l", "2", "-s", "1", "-n", str(self.nprocs), "-o", "mem",
                       "-stats", "pid,user,cpu,mem,command"], timeout=20)
            try:
                self._parse_top(out)
            except Exception:
                pass
            time.sleep(1)

    def _parse_top(self, out):
        lines = out.splitlines()
        hdr = [i for i, l in enumerate(lines) if re.match(r"\s*PID\s+USER", l)]
        procs = []
        if hdr:
            for l in lines[hdr[-1] + 1:]:
                parts = l.split(None, 4)
                if len(parts) < 5 or not parts[0].isdigit():
                    continue
                procs.append({"pid": int(parts[0]), "user": parts[1], "cpu": num(parts[2]),
                              "host_mem": parse_size(parts[3]), "command": parts[4].strip(),
                              "dev": None, "type": "Unified", "gpu_mem": None})
        if procs:   # full command lines
            out2 = run(["ps", "-o", "pid=,command=", "-p", ",".join(str(p["pid"]) for p in procs)])
            full = {}
            for l in out2.splitlines():
                parts = l.strip().split(None, 1)
                if len(parts) == 2 and parts[0].isdigit():
                    full[int(parts[0])] = parts[1]
            for p in procs:
                p["command"] = redact(full.get(p["pid"], p["command"]))[:500]
        cpu = re.findall(r"CPU usage:\s*([\d.]+)% user,\s*([\d.]+)% sys", out)
        mem = re.findall(r"PhysMem:\s*(\S+) used", out)
        with self.lock:
            self.top = {"procs": procs,
                        "cpu": (float(cpu[-1][0]) + float(cpu[-1][1])) if cpu else None,
                        "mem_used": parse_size(mem[-1]) if mem else None}

    def _pm_loop(self):
        while True:
            out = run(self.pm_cmd + ["--samplers", "gpu_power,thermal", "-i", "1000", "-n", "1"],
                      timeout=20)
            if "GPU" not in out:
                with self.lock:
                    self.pm = {}
                time.sleep(60)  # not permitted (yet): no root / no sudo rule. Retry so a new rule is picked up.
                continue
            d = {}
            m = re.search(r"GPU HW active frequency:\s*([\d.]+)\s*MHz", out)
            if m:
                d["freq"] = float(m.group(1))
            m = re.search(r"GPU Power:\s*([\d.]+)\s*mW", out)
            if m:
                d["power"] = float(m.group(1)) / 1000.0
            m = re.search(r"Current pressure level:\s*(\w+)", out)
            if m:
                d["thermal"] = m.group(1)
            with self.lock:
                self.pm = d
            time.sleep(1)

    def collect(self):
        out = run(["ioreg", "-r", "-d", "1", "-w", "0", "-c", "IOAccelerator"])
        stats = {}
        m = re.search(r'"PerformanceStatistics"\s*=\s*\{(.*?)\}', out)
        if m:
            for k, v in re.findall(r'"([^"]+)"\s*=\s*(\d+)', m.group(1)):
                stats[k] = int(v)
        cores = re.search(r'"gpu-core-count"\s*=\s*(\d+)', out)
        limit, is_default = self.wired_limit()
        with self.lock:
            pm, top = dict(self.pm), dict(self.top)
        gpu = {
            "index": 0, "name": self.chip,
            "util": stats.get("Device Utilization %"),
            # "Alloc system memory" = memory held for the GPU (model weights, KV cache): the VRAM-like
            # number. "In use system memory" only counts what is being touched right now.
            "mem_used": stats.get("Alloc system memory", stats.get("In use system memory")),
            "mem_in_use": stats.get("In use system memory"),
            "mem_total": limit, "mem_total_is_default": is_default,
            "unified_total": self.memsize,
            "temp": None, "thermal": pm.get("thermal"),
            "power": pm.get("power"), "power_limit": None,
            "fan": None, "clock_gr": pm.get("freq"), "clock_mem": None,
            "bus": ("%d-core GPU" % int(cores.group(1))) if cores else "Unified memory",
        }
        host = {"cpu": top["cpu"], "mem_used": top["mem_used"], "mem_total": self.memsize}
        return {"kind": "apple", "host": host, "gpus": [gpu], "procs": top["procs"],
                "power_metrics": bool(pm)}


# ----------------------------------------------------------------------------- no GPU

class HostOnly:
    def __init__(self):
        self.host = LinuxHost() if sys.platform.startswith("linux") else None

    def collect(self):
        h = self.host.host_stats() if self.host else {"cpu": None, "mem_used": None, "mem_total": None}
        return {"kind": "none", "host": h, "gpus": [], "procs": []}


# ----------------------------------------------------------------------------- demo data

class Demo:
    """Fake data for trying the dashboard without hardware: --demo nvidia4 | apple"""

    def __init__(self, mode):
        self.mode = mode
        self.t0 = time.time()

    def collect(self):
        t = time.time() - self.t0
        if self.mode == "nvidia1":
            util = max(0, min(100, 35 + 30 * math.sin(t / 7) + random.uniform(-6, 6)))
            return {"kind": "nvidia", "host": {"cpu": 4.0 + random.uniform(-1, 1), "mem_used": int(14.2 * GiB), "mem_total": int(125.8 * GiB)},
                    "gpus": [{"index": 0, "name": "NVIDIA CMP 170HX", "util": round(util), "mem_used": int(56.6 * GiB),
                              "mem_total": 64 * GiB, "temp": 36 + int(util / 10), "power": round(45 + util * 1.4), "power_limit": 250,
                              "fan": None, "clock_gr": 1140, "clock_mem": 1728, "bus": "PCIe GEN 2@16x",
                              "pcie_rx": round(120 + 80 * math.sin(t)), "pcie_tx": 64.0}],
                    "procs": [{"pid": 18342, "user": "llm", "dev": 0, "type": "Compute", "gpu_mem": int(56.4 * GiB), "cpu": 22.0,
                               "host_mem": int(9.1 * GiB), "command": "VLLM::EngineCore"}]}
        if self.mode == "applemax":
            util = max(0, min(100, 20 + 25 * math.sin(t / 4) + random.uniform(-5, 5)))
            return {"kind": "apple", "host": {"cpu": 11.0 + random.uniform(-2, 2), "mem_used": int(31.5 * GiB), "mem_total": 36 * GiB},
                    "gpus": [{"index": 0, "name": "Apple M5 Max", "util": round(util), "mem_used": int(17.2 * GiB), "mem_in_use": int(1.1 * GiB),
                              "mem_total": int(24 * GiB), "mem_total_is_default": True, "unified_total": 36 * GiB,
                              "temp": None, "thermal": "Nominal", "power": round(4 + util * 0.4, 1), "power_limit": None,
                              "fan": None, "clock_gr": 1296 if util > 5 else 338, "clock_mem": None, "bus": "32-core GPU"}],
                    "procs": [{"pid": 912, "user": "llm", "cpu": 35.0, "host_mem": int(9.8 * GiB), "dev": None, "type": "Unified", "gpu_mem": None,
                               "command": "/opt/homebrew/bin/llama-server -m models/gemma-4-12b-it-Q4_K_M.gguf --port 8001"},
                              {"pid": 913, "user": "llm", "cpu": 4.0, "host_mem": int(3.5 * GiB), "dev": None, "type": "Unified", "gpu_mem": None,
                               "command": "/Users/llm/mlx-tts/bin/python -m mlx_audio.server --port 8881"}],
                    "power_metrics": True}
        if self.mode == "nas":
            return {"kind": "nvidia", "host": {"cpu": 9.0 + random.uniform(-2, 2), "mem_used": int(88 * GiB), "mem_total": int(251 * GiB)},
                    "gpus": [{"index": 0, "name": "NVIDIA A2", "util": round(18 + 6 * math.sin(t / 3)), "mem_used": int(1.6 * GiB),
                              "mem_total": int(15 * GiB), "temp": 47, "power": 24.5, "power_limit": 60, "fan": None,
                              "clock_gr": 1770, "clock_mem": 6251, "bus": "PCIe GEN 4@8x", "pcie_rx": 42.0, "pcie_tx": 18.0}],
                    "procs": [{"pid": 4100 + i, "user": "apps", "dev": 0, "type": "Compute", "gpu_mem": int(118 * MiB), "cpu": 6.0,
                               "host_mem": int(180 * MiB),
                               "command": "/usr/lib/ffmpeg/7.0/bin/ffmpeg -hwaccel cuda -rtsp_transport tcp -i rtsp://admin:***@10.0.50.%d:554/live0" % (21 + i)}
                              for i in range(4)] +
                             [{"pid": 5120, "user": "apps", "dev": 0, "type": "Compute", "gpu_mem": int(410 * MiB), "cpu": 18.0,
                               "host_mem": int(320 * MiB), "command": "/usr/lib/plexmediaserver/Plex Transcoder -codec:0 hevc_cuvid"}]}
        if self.mode == "invoke":
            util = max(0, min(100, 60 + 35 * math.sin(t / 4)))
            return {"kind": "nvidia", "host": {"cpu": 3.0, "mem_used": int(8.5 * GiB), "mem_total": int(125.8 * GiB)},
                    "gpus": [{"index": 0, "name": "NVIDIA CMP 170HX", "util": round(util), "mem_used": int(21.3 * GiB),
                              "mem_total": 64 * GiB, "temp": 41, "power": 160, "power_limit": 250, "fan": None,
                              "clock_gr": 1140, "clock_mem": 1728, "bus": "PCIe GEN 2@16x", "pcie_rx": 120.0, "pcie_tx": 12.0}],
                    "procs": [{"pid": 4412, "user": "llm", "dev": 0, "type": "Compute", "gpu_mem": int(21.1 * GiB), "cpu": 98.0,
                               "host_mem": int(6.2 * GiB), "command": "/home/llm/invokeai/.venv/bin/python /home/llm/invokeai/.venv/bin/invokeai-web"}]}
        if self.mode == "apple":
            util = max(0, min(100, 55 + 40 * math.sin(t / 6) + random.uniform(-8, 8)))
            gpus = [{"index": 0, "name": "Apple M5 Ultra", "util": round(util),
                     "mem_used": int(212.4 * GiB + 2 * GiB * math.sin(t / 9)),
                     "mem_in_use": int(3 * GiB), "mem_total": 240000 * MiB,
                     "mem_total_is_default": False, "unified_total": 256 * GiB,
                     "temp": None, "thermal": "Nominal", "power": round(40 + util * 0.9, 1),
                     "power_limit": None, "fan": None, "clock_gr": 1380 if util > 5 else 338,
                     "clock_mem": None, "bus": "80-core GPU"}]
            procs = [
                {"pid": 812, "user": "llm", "cpu": 96.4, "host_mem": int(208.9 * GiB),
                 "command": "/Users/llm/models/.venv/bin/python -m tensorfold.server --port 8001",
                 "dev": None, "type": "Unified", "gpu_mem": None},
                {"pid": 640, "user": "llm", "cpu": 2.1, "host_mem": int(2.4 * GiB),
                 "command": "/Applications/oMLX.app/Contents/MacOS/oMLX", "dev": None,
                 "type": "Unified", "gpu_mem": None},
                {"pid": 401, "user": "_windowserver", "cpu": 3.0, "host_mem": int(0.6 * GiB),
                 "command": "WindowServer", "dev": None, "type": "Unified", "gpu_mem": None},
            ]
            return {"kind": "apple", "host": {"cpu": 9.5 + random.uniform(-2, 2),
                                              "mem_used": int(231 * GiB), "mem_total": 256 * GiB},
                    "gpus": gpus, "procs": procs, "power_metrics": True}
        n = 4
        gpus, procs = [], []
        for i in range(n):
            util = max(0, min(100, 50 + 45 * math.sin(t / 5 + i * 0.7) + random.uniform(-5, 5)))
            used = 63.62 * GiB + i * 0.004 * GiB
            gpus.append({"index": i, "name": "NVIDIA CMP 170HX", "util": round(util),
                         "mem_used": int(used), "mem_total": 64 * GiB, "temp": 33 + int(util / 8),
                         "power": round(40 + util * 1.6), "power_limit": 250, "fan": None,
                         "clock_gr": 1140, "clock_mem": 1728, "bus": "PCIe GEN 2@16x",
                         "pcie_rx": round(390 + 50 * math.sin(t + i)), "pcie_tx": round(683 - i * 100)})
            procs.append({"pid": 260683 + i, "user": "llm", "dev": i, "type": "Compute",
                          "gpu_mem": int(64508 * MiB), "cpu": round(util / 30, 1),
                          "host_mem": int((52348 + i * 10) * MiB), "command": "VLLM::Worker_TP%d" % i})
        return {"kind": "nvidia", "host": {"cpu": 6 + random.uniform(-2, 2), "mem_used": int(214 * GiB),
                                           "mem_total": int(251.5 * GiB)},
                "gpus": gpus, "procs": procs}


# ----------------------------------------------------------------------------- services

# pinned services may only point at the machine itself (no fetching other hosts through it)
LOCAL_URL_RE = re.compile(r"^https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?(?:/[\w./-]*)?$")
KNOWN_PORTS = [8000, 8001, 8002, 8003, 8080, 8081, 8188, 8880, 8881, 9090, 11434, 1234, 7860, 8096, 32400]
SKIP_PORTS = {22, 25, 53, 80, 111, 139, 443, 445, 548, 631, 2049, 3306, 5353, 5432, 5900, 6379, 9100, 9180}
if sys.platform == "darwin":
    SKIP_PORTS |= {3283, 5000, 7000, 49152}   # Apple Remote Desktop, AirPlay Receiver (5000/7000)
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
KIND_LABEL = {"vllm": "vLLM", "llamacpp": "llama.cpp", "ollama": "Ollama", "openai": "OpenAI API",
              "invokeai": "InvokeAI", "comfyui": "ComfyUI", "plex": "Plex", "jellyfin": "Jellyfin", "frigate": "Frigate",
              "custom": "service"}


def http_get(url, timeout=0.8, key=None, limit=4000000, want_headers=False):
    hdrs = {"User-Agent": "gpuwatch"}
    if key:
        hdrs["Authorization"] = "Bearer " + key
    try:
        with _OPENER.open(urllib.request.Request(url, headers=hdrs), timeout=timeout) as r:
            body = r.read(limit).decode("utf-8", "replace")
            return (r.status, body, dict(r.headers)) if want_headers else (r.status, body)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(20000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return (e.code, body, dict(e.headers or {})) if want_headers else (e.code, body)
    except Exception:
        return (None, "", {}) if want_headers else (None, "")


def jload(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def prom_sum(text, name):
    tot = None
    n = len(name)
    for l in text.splitlines():
        if l.startswith(name) and len(l) > n and l[n] in " {":
            try:
                tot = (tot or 0.0) + float(l.rsplit(None, 1)[1])
            except (ValueError, IndexError):
                pass
    return tot


def listening_ports():
    """{port: (connect_host, process_name)} for TCP listeners (process names only where visible)."""
    ports = {}

    def add(addr, proc):
        m = re.match(r"^(.*):(\d+)$", addr)
        if not m:
            return
        host, port = m.group(1), int(m.group(2))
        if host in ("*", "0.0.0.0", "[::]", "::", "", "127.0.0.1", "[::ffff:0.0.0.0]"):
            host = "127.0.0.1"
        elif host in ("[::1]", "::1"):
            host = "[::1]"
        elif ":" in host and not host.startswith("["):
            host = "[%s]" % host
        if port not in ports or (proc and not ports[port][1]):
            ports[port] = (host, proc)

    if sys.platform == "darwin":
        lsof = "/usr/sbin/lsof" if os.path.exists("/usr/sbin/lsof") else "lsof"
        for l in run([lsof, "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=15).splitlines()[1:]:
            parts = l.split()
            if len(parts) >= 9:
                add(parts[8], parts[0].replace("\\x20", " "))
        if not ports:   # fallback: netstat (no process names), e.g. "tcp4 0 0 *.8000 *.* LISTEN"
            for l in run(["/usr/sbin/netstat", "-an", "-p", "tcp"]).splitlines():
                parts = l.split()
                if len(parts) >= 6 and parts[-1] == "LISTEN":
                    loc = parts[3]
                    if "." in loc:
                        h, _, prt = loc.rpartition(".")
                        add("%s:%s" % (h, prt), "")
    else:
        ss = next((p for p in ("/usr/bin/ss", "/bin/ss", "/usr/sbin/ss") if os.path.exists(p)), None)
        if ss:
            for l in run([ss, "-ltnpH"]).splitlines():
                parts = l.split()
                if len(parts) >= 4:
                    m = re.search(r'users:\(\("([^"]+)"', l)
                    add(parts[3], m.group(1) if m else "")
        if not ports:   # fallback: the kernel's own table (no process names)
            for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
                try:
                    with open(fn) as f:
                        rows = f.read().splitlines()[1:]
                except OSError:
                    continue
                for row in rows:
                    cols = row.split()
                    if len(cols) > 3 and cols[3] == "0A":          # 0A = LISTEN
                        hexaddr, hexport = cols[1].split(":")
                        local = hexaddr.strip("0") == "" or hexaddr in ("0100007F", "00000000000000000000000001000000")
                        add(("127.0.0.1" if local else "*") + ":%d" % int(hexport, 16), "")
    return ports


def _looks_like_api_auth(st, body, headers):
    if st != 401:
        return False
    if "bearer" in str(headers.get("WWW-Authenticate", headers.get("www-authenticate", ""))).lower():
        return True
    j = jload(body)
    return isinstance(j, dict) and any(k in j for k in ("error", "detail", "message"))


def identify(base, key=None, loose=False):
    st, body = http_get(base + "/identity")                       # Plex (no token needed)
    if st == 200 and "<MediaContainer" in body and "machineIdentifier" in body:
        m = re.search(r'<MediaContainer[^>]*\sversion="([^"]+)"', body)
        return {"kind": "plex", "version": m.group(1).split("-")[0] if m else ""}
    st, body = http_get(base + "/System/Info/Public")              # Jellyfin
    j = jload(body) if st == 200 else None
    if isinstance(j, dict) and "jellyfin" in str(j.get("ProductName", "")).lower():
        return {"kind": "jellyfin", "version": str(j.get("Version", ""))}
    st, body = http_get(base + "/api/stats")                      # Frigate (unauthenticated internal API)
    j = jload(body) if st == 200 else None
    if isinstance(j, dict) and isinstance(j.get("cameras"), dict) and "service" in j:
        st2, ver = http_get(base + "/api/version")
        return {"kind": "frigate", "version": ver.strip()[:20] if st2 == 200 else "", "cameras": len(j["cameras"])}
    st, body, hdrs = http_get(base + "/v1/models", key=key, want_headers=True, timeout=2.0)
    if st == 200:
        j = jload(body)
        if isinstance(j, dict) and isinstance(j.get("data"), list):
            data = [m for m in j["data"] if isinstance(m, dict)]
            models = [str(m.get("id")) for m in data if m.get("id")]
            owners = {str(m.get("owned_by", "")).lower() for m in data}
            kind = "openai"
            if "vllm" in owners:
                kind = "vllm"
            elif "llamacpp" in owners:
                kind = "llamacpp"
            else:
                st2, b2 = http_get(base + "/props", key=key)
                if st2 == 200 and "default_generation_settings" in b2:
                    kind = "llamacpp"
                else:
                    st3, b3 = http_get(base + "/api/ps")
                    if st3 == 200 and '"models"' in b3:
                        kind = "ollama"
            return {"kind": kind, "models": models, "owner": next(iter(sorted(o for o in owners if o)), "")[:30]}
    elif loose and _looks_like_api_auth(st, body, hdrs):
        return {"kind": "openai", "models": [], "auth": True}
    st, body = http_get(base + "/api/v1/app/version")
    j = jload(body) if st == 200 else None
    if isinstance(j, dict) and "version" in j:
        return {"kind": "invokeai", "version": str(j.get("version"))}
    st, body = http_get(base + "/system_stats")
    j = jload(body) if st == 200 else None
    if isinstance(j, dict) and "devices" in j:
        return {"kind": "comfyui"}
    st, body = http_get(base + "/api/ps")
    j = jload(body) if st == 200 else None
    if isinstance(j, dict) and isinstance(j.get("models"), list):
        return {"kind": "ollama", "models": []}
    return None


class Services:
    """Finds model/image servers on this machine and polls their load."""

    def __init__(self, pins=None):
        self.pins = pins or []
        self.lock = threading.Lock()
        self.found = []          # list of service dicts (with private _base/_key)
        self.counters = {}       # base -> (tokens, time)
        self.negative = {}       # base -> time it was last found to be "not a known service"
        threading.Thread(target=self._loop, daemon=True).start()

    def snapshot(self):
        with self.lock:
            return [{k: v for k, v in s.items() if not k.startswith("_")} for s in self.found]

    def diag(self):
        return dict(getattr(self, "_diag", {}))

    def _loop(self):
        last = 0
        while True:
            try:
                if time.time() - last > 30:
                    self._discover()
                    last = time.time()
                self._poll()
            except Exception:
                pass
            time.sleep(2)

    def _discover(self):
        ports = listening_ports()
        self._diag = {"listening": len(ports), "named": sum(1 for _, (h, p) in ports.items() if p)}
        cands = {}
        for port, (host, proc) in ports.items():
            if port in SKIP_PORTS or port >= 49152:
                continue
            cands[port] = (host, proc)
        for port in KNOWN_PORTS:
            cands.setdefault(port, ("127.0.0.1", ""))
        items = sorted(cands.items())[:200]
        now = time.time()
        known = {f["_base"] for f in self.found}

        def probe(item):
            port, (host, proc) = item
            base = "http://%s:%d" % (host, port)
            # ports that weren't a recognised service are re-checked every 10 min, not every pass
            if base not in known and now - self.negative.get(base, 0) < 600:
                return None
            r = identify(base, loose=port in KNOWN_PORTS)
            if r:
                r.update(port=port, proc=proc, _base=base)
                self.negative.pop(base, None)
            else:
                self.negative[base] = now
            return r

        found = []
        try:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=16) as ex:
                found = [r for r in ex.map(probe, items) if r]
        except Exception:
            found = [r for r in map(probe, items) if r]
        # pinned services (from the dashboard): always shown, may carry an API key
        pinned_ports = set()
        for pin in self.pins[:8]:
            url = str(pin.get("url", "")).rstrip("/")
            if not url or not LOCAL_URL_RE.match(url):
                continue
            key = pin.get("key") or None
            r = identify(url, key=key, loose=True) or {"kind": "custom", "models": []}
            m = re.search(r":(\d+)$", url.split("//")[-1])
            port = int(m.group(1)) if m else None
            r.update(port=port, proc="", pinned=True, name=pin.get("name") or "", _base=url, _key=key)
            pinned_ports.add(port)
            found = [f for f in found if f.get("port") != port]
            found.append(r)
        for f in found:
            if not f.get("name"):
                proc = (f.get("proc") or "").lower()
                label = KIND_LABEL.get(f["kind"], f["kind"])
                models = " ".join(f.get("models") or []).lower()
                owner = (f.get("owner") or "").lower()
                if f["kind"] == "openai":
                    if "omlx" in proc or "omlx" in owner:
                        label = "oMLX"
                    elif "tensorfold" in proc or "tensorfold" in owner:
                        label = "TensorFold"
                    elif any(w in models for w in ("kokoro", "whisper", "parakeet", "tts", "stt")):
                        label = "Speech (mlx-audio)" if "mlx" in models else "Speech API"
                    elif "mlx" in proc or "mlx" in models:
                        label = "MLX server"
                f["name"] = label
        found.sort(key=lambda f: (f.get("port") or 0))
        with self.lock:
            old = {f["_base"]: f for f in self.found}
            for f in found:   # keep last live numbers until the next poll
                o = old.get(f["_base"])
                if o:
                    for k in ("running", "queued", "tps", "loaded"):
                        if k in o:
                            f.setdefault(k, o[k])
            self.found = found

    def _poll(self):
        with self.lock:
            items = list(self.found)
        now = time.time()
        for f in items:
            base, key, kind = f["_base"], f.get("_key"), f["kind"]
            upd = {}
            if kind in ("vllm", "llamacpp"):
                st, body = http_get(base + "/metrics", key=key, timeout=1.5)
                if st == 200 and body:
                    if kind == "vllm":
                        run_, que, tok = (prom_sum(body, "vllm:num_requests_running"),
                                          prom_sum(body, "vllm:num_requests_waiting"),
                                          prom_sum(body, "vllm:generation_tokens_total"))
                    else:
                        run_, que, tok = (prom_sum(body, "llamacpp:requests_processing"),
                                          prom_sum(body, "llamacpp:requests_deferred"),
                                          prom_sum(body, "llamacpp:tokens_predicted_total"))
                    upd["running"], upd["queued"] = run_, que
                    if tok is not None:
                        prev = self.counters.get(base)
                        if prev and now > prev[1] and tok >= prev[0]:
                            upd["tps"] = round((tok - prev[0]) / (now - prev[1]), 1)
                        self.counters[base] = (tok, now)
                elif kind == "llamacpp":
                    st, body = http_get(base + "/slots", key=key)
                    j = jload(body) if st == 200 else None
                    if isinstance(j, list):
                        upd["running"] = sum(1 for x in j if isinstance(x, dict) and x.get("is_processing"))
            elif kind == "ollama":
                st, body = http_get(base + "/api/ps")
                j = jload(body) if st == 200 else None
                if isinstance(j, dict):
                    upd["loaded"] = [str(m.get("name")) for m in j.get("models", []) if isinstance(m, dict)]
            elif kind == "invokeai":
                st, body = http_get(base + "/api/v1/queue/default/status")
                j = jload(body) if st == 200 else None
                if isinstance(j, dict):
                    q = j.get("queue") or {}
                    upd["running"] = q.get("in_progress")
                    upd["queued"] = q.get("pending")
                    upd["busy"] = bool((j.get("processor") or {}).get("is_processing")) or bool(q.get("in_progress"))
            elif kind == "frigate":
                st, body = http_get(base + "/api/stats", timeout=1.5)
                j = jload(body) if st == 200 else None
                if isinstance(j, dict) and isinstance(j.get("cameras"), dict):
                    cams = j["cameras"]
                    upd["cameras"] = len(cams)
                    upd["fps"] = round(sum(float((c or {}).get("camera_fps") or 0) for c in cams.values()), 1)
            elif kind == "comfyui":
                st, body = http_get(base + "/queue")
                j = jload(body) if st == 200 else None
                if isinstance(j, dict):
                    upd["running"] = len(j.get("queue_running") or [])
                    upd["queued"] = len(j.get("queue_pending") or [])
            if upd:
                with self.lock:
                    for g in self.found:
                        if g["_base"] == base:
                            g.update(upd)


def demo_services(mode):
    if mode == "nvidia1":
        return [{"kind": "vllm", "name": "vLLM", "port": 8000, "models": ["qwen3.8-27b"], "running": 1, "queued": 0,
                 "tps": round(28 + 6 * math.sin(time.time() / 3), 1)}]
    if mode == "applemax":
        return [{"kind": "llamacpp", "name": "llama.cpp", "port": 8001, "models": ["gemma4-12b"], "running": 1},
                {"kind": "llamacpp", "name": "llama.cpp", "port": 8002, "models": ["qwen3-1.7b"], "running": 0},
                {"kind": "openai", "name": "Speech (mlx-audio)", "port": 8881, "models": ["mlx-community/Kokoro-82M-bf16", "mlx-community/parakeet-tdt-0.6b-v2"]}]
    if mode == "nas":
        return [{"kind": "jellyfin", "name": "Jellyfin", "port": 8096, "version": "10.11.2"},
                {"kind": "ollama", "name": "Ollama", "port": 11434, "models": [], "loaded": []},
                {"kind": "plex", "name": "Plex", "port": 32400, "version": "1.42.2"},
                {"kind": "frigate", "name": "Frigate", "port": 5000, "version": "0.16.2", "cameras": 4, "fps": 20.0}]
    if mode == "apple":
        return [{"kind": "openai", "name": "oMLX", "port": 8000, "models": ["Qwen3.8-27B-MLX-8bit", "UI-TARS-1.5-7B-8bit"], "auth": False},
                {"kind": "openai", "name": "OpenAI API", "port": 8001, "models": ["DeepSeek-V4.1-Flash"], "proc": "python3.12"}]
    if mode == "invoke":
        return [{"kind": "invokeai", "name": "InvokeAI", "port": 9090, "version": "6.9.0", "running": 1, "queued": 2, "busy": True}]
    t = time.time()
    r = int(2 + 2 * math.sin(t / 7))
    return [{"kind": "vllm", "name": "vLLM", "port": 8000, "models": ["dsv41-flash"], "running": r, "queued": max(0, r - 3),
             "tps": round(30 + 25 * math.sin(t / 5), 1) if r else 0.0}]


# ----------------------------------------------------------------------------- agent

def detect():
    if sys.platform == "darwin":
        out = run(["sysctl", "-n", "hw.optional.arm64"]).strip()
        if out == "1":
            return Apple()
    if shutil.which("nvidia-smi"):
        return Nvidia()
    return HostOnly()


class Agent:
    def __init__(self, args):
        self.args = args
        self.source = Demo(args.demo) if args.demo else detect()
        self.hostname = args.name or socket.gethostname().split(".")[0]
        self.lock = threading.Lock()
        self.snap = {"kind": "starting", "gpus": [], "procs": [], "host": {}}
        self.hist = {}
        self.config_path = os.path.join(args.state_dir or HERE, "hosts.json")
        self.hosts = self._load_hosts()
        self.services = Services()
        threading.Thread(target=self._loop, daemon=True).start()

    # hosts list shown by the dashboard
    def _load_hosts(self):
        try:
            with open(self.config_path) as f:
                hosts = json.load(f).get("hosts", [])
                return [h for h in (norm_host(x) for x in hosts) if h]
        except Exception:
            pass
        seed = [h for h in (norm_host(x) for x in (self.args.hosts or "").split(",")) if h]
        return seed

    def save_hosts(self, hosts):
        clean = []
        for h in hosts:
            h = norm_host(str(h))
            if h and re.match(r"^[\w.\-\[\]:]+$", h) and h not in clean:
                clean.append(h)
        self.hosts = clean[:64]
        try:
            with open(self.config_path, "w") as f:
                json.dump({"hosts": self.hosts}, f, indent=2)
        except Exception as e:
            sys.stderr.write("gpuwatch: could not save %s: %s\n" % (self.config_path, e))
        return self.hosts

    def _loop(self):
        while True:
            t0 = time.time()
            try:
                snap = self.source.collect()
            except Exception as e:
                snap = {"kind": "error", "error": str(e), "gpus": [], "procs": [], "host": {}}
            snap.update(hostname=self.hostname, version=VERSION, ts=time.time(),
                        interval=self.args.interval, services=self.services.snapshot())
            with self.lock:
                self.snap = snap
                for g in snap.get("gpus", []):
                    d = self.hist.setdefault(g["index"], deque())
                    mp = (100.0 * g["mem_used"] / g["mem_total"]) if g.get("mem_used") is not None and g.get("mem_total") else None
                    d.append((snap["ts"], g.get("util"), mp))
                    while d and snap["ts"] - d[0][0] > HISTORY_SECONDS:
                        d.popleft()
            time.sleep(max(0.05, self.args.interval - (time.time() - t0)))

    def snapshot(self):
        with self.lock:
            return dict(self.snap)

    def history(self):
        now = time.time()
        with self.lock:
            return {"now": now, "gpus": {str(k): [[round(now - t, 2), u, m] for t, u, m in v]
                                         for k, v in self.hist.items()}}


    def snapshots(self):
        return [("localhost", self.snapshot(), None)]

    # --- used by the HTTP handler
    def config(self):
        return {"mode": "agent", "hosts": self.hosts, "self": self.hostname, "version": VERSION}

    def proxy(self, target, sub):
        target = norm_host(target)
        if target not in self.hosts:
            return 403, {"error": "host not in saved list"}
        try:
            with urllib.request.urlopen("http://%s/%s" % (target, sub), timeout=3) as r:
                return 200, r.read()
        except Exception as e:
            return 502, {"error": "unreachable: %s" % e}


# ----------------------------------------------------------------------------- hub (agentless, SSH)

def record_hist(hist, gpus, ts):
    for g in gpus or []:
        d = hist.setdefault(g["index"], deque())
        mp = (100.0 * g["mem_used"] / g["mem_total"]) if g.get("mem_used") is not None and g.get("mem_total") else None
        d.append((ts, g.get("util"), mp))
        while d and ts - d[0][0] > HISTORY_SECONDS:
            d.popleft()


def hist_json(hist):
    now = time.time()
    return {"now": now, "gpus": {str(k): [[round(now - t, 2), u, m] for t, u, m in v]
                                 for k, v in hist.items()}}


_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$")
_HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_IP6_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")


def _split_target(t):
    user = None
    if "@" in t:
        user, t = t.split("@", 1)
    port = None
    if t.startswith("["):
        host, sep, rest = t[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            return None
        port = rest[1:] or None
        if not _IP6_RE.match(host):
            return None
        host = "[%s]" % host
    else:
        if t.count(":") == 1:
            t, port = t.split(":")
        host = t
        if not _HOST_RE.match(host or ""):
            return None
    if user is not None and not _USER_RE.match(user):
        return None
    if port is not None and (not port.isdigit() or not 1 <= int(port) <= 65535):
        return None
    return user, host, port


def norm_target(t):
    """SSH target: [user@]host[:port], strictly validated (no option-like or odd characters)."""
    t = (t or "").strip()
    for pre in ("ssh://", "http://", "https://"):
        if t.startswith(pre):
            t = t[len(pre):]
    t = t.split("/")[0]
    if len(t) > 120:
        return ""
    parts = _split_target(t)
    if not parts:
        return ""
    user, host, port = parts
    return (user + "@" if user else "") + host + (":" + port if port else "")


def parse_target(t, default_user):
    parts = _split_target(t)
    if not parts:
        raise ValueError("invalid target")
    user, host, port = parts
    user = user or default_user
    if not _USER_RE.match(user):
        raise ValueError("invalid ssh user")
    return user, host.strip("[]"), port or "22"


def friendly_ssh_error(lines, got_data):
    text = " | ".join(l for l in lines if l)
    low = text.lower()
    if "permission denied" in low:
        return "SSH key not authorized on this machine (Manage machines shows the key)"
    if "host key verification failed" in low or "remote host identification has changed" in low:
        return "host key changed - delete its line from data/ssh/known_hosts"
    if "python3: command not found" in low or "python3: not found" in low:
        return "python3 not found on this machine"
    if "xcode-select" in low or "no developer tools" in low:
        return "python3 needs the Xcode Command Line Tools on this Mac (xcode-select --install)"
    if "connection refused" in low:
        return "SSH connection refused (is Remote Login / sshd on?)"
    if "timed out" in low or "no route to host" in low:
        return "no response (machine off or unreachable)"
    if text:
        return text[-200:]
    return "connection closed" if got_data else "no data from remote"


DEMO_FLEET = [  # target, hostname, demo mode
    ("10.0.0.30", "gpu-rig", "nvidia4"),
    ("10.0.0.31", "vllm-node", "nvidia1"),
    ("10.0.0.32", "image-gen", "invoke"),
    ("10.0.0.40", "mac-studio-ultra", "apple"),
    ("10.0.0.41", "mac-studio-max", "applemax"),
    ("10.0.0.10", "nas", "nas"),
]


class Remote:
    """One persistent SSH session that runs the collector remotely and streams JSON lines back."""

    def __init__(self, hub, target):
        self.hub, self.target = hub, target
        self.lock = threading.Lock()
        self.snap, self.err, self.hist = None, "connecting", {}
        self.stopped, self.proc = False, None
        threading.Thread(target=self._run, daemon=True).start()

    def restart(self):
        """Reconnect (e.g. after pinned services changed); the run loop starts a new session."""
        try:
            if self.proc:
                self.proc.kill()
        except Exception:
            pass

    def close(self):
        self.stopped = True
        try:
            if self.proc:
                self.proc.kill()
        except Exception:
            pass

    def _demo(self, name, mode):
        src = Demo(mode)
        while not self.stopped:
            snap = src.collect()
            snap.update(hostname=name, version=VERSION, interval=self.hub.interval, services=demo_services(mode))
            now = time.time()
            snap["ts"] = now
            with self.lock:
                self.snap, self.err = snap, None
                record_hist(self.hist, snap.get("gpus"), now)
            time.sleep(self.hub.interval)

    def _run(self):
        if self.hub.demo_fleet:
            for target, name, mode in DEMO_FLEET:
                if target == self.target:
                    return self._demo(name, mode)
        backoff = 3
        while not self.stopped:
            try:
                user, host, port = parse_target(self.target, self.hub.ssh_user)
            except ValueError as e:
                with self.lock:
                    self.err = str(e)
                return
            remote_cmd = "python3 - --stream --interval %s %s" % (self.hub.interval, self.hub.remote_args)
            script = self.hub.script.replace('PINS_JSON = "[]"', "PINS_JSON = %r" % json.dumps(self.hub.pins.get(self.target, [])), 1)
            cmd = ["ssh", "-F", "/dev/null", "-T", "-i", self.hub.key, "-p", port,
                   "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + self.hub.known_hosts,
                   "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
                   "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none", "-o", "Tunnel=no",
                   "-o", "ConnectTimeout=6", "-o", "ServerAliveInterval=5",
                   "-o", "ServerAliveCountMax=3", "-o", "LogLevel=ERROR",
                   "-l", user, "--", host, remote_cmd.strip()]
            errlines = deque(maxlen=6)
            got = False
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, universal_newlines=True, bufsize=1)
                self.proc = p

                def drain():
                    for l in p.stderr:
                        errlines.append(l.strip()[:300])
                threading.Thread(target=drain, daemon=True).start()
                try:
                    p.stdin.write(script)
                    p.stdin.close()
                except Exception:
                    pass
                while True:
                    line = p.stdout.readline(2000000)      # bounded: a machine can't flood the hub
                    if not line:
                        break
                    if not line.endswith("\n"):
                        p.stdout.readline(2000000)         # discard the rest of an oversized line
                        continue
                    try:
                        snap = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(snap, dict):
                        continue
                    got, backoff = True, 3
                    now = time.time()
                    snap["ts"] = now
                    with self.lock:
                        self.snap, self.err = snap, None
                        record_hist(self.hist, snap.get("gpus"), now)
                p.wait()
                time.sleep(0.2)
                msg = friendly_ssh_error(list(errlines), got)
            except Exception as e:
                msg = str(e)
            with self.lock:
                self.err = msg
            if self.stopped:
                break
            time.sleep(backoff)
            backoff = min(30, backoff * 2)


class Hub:
    def __init__(self, args):
        self.args = args
        self.interval = args.interval
        data = args.state_dir or os.environ.get("GPUWATCH_DATA") or "/data"
        sshdir = os.path.join(data, "ssh")
        os.makedirs(sshdir, mode=0o700, exist_ok=True)
        self.ssh_user = args.ssh_user or os.environ.get("GPUWATCH_SSH_USER") or "root"
        self.remote_args = os.environ.get("GPUWATCH_REMOTE_ARGS", "")
        self.key = os.path.join(sshdir, "id_ed25519")
        self.known_hosts = os.path.join(sshdir, "known_hosts")
        if not os.path.exists(self.key):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "gpuwatch-hub", "-f", self.key],
                           check=True)
        with open(self.key + ".pub") as f:
            self.pubkey = f.read().strip()
        with open(os.path.abspath(__file__)) as f:
            self.script = f.read()
        self.hostname = args.name or "gpuwatch-hub"
        self.hub_ip = os.environ.get("GPUWATCH_HUB_IP", "")
        self.demo_fleet = os.environ.get("GPUWATCH_DEMO_FLEET", "") not in ("", "0", "false", "no")
        self.auth = Auth(data)
        self.config_path = os.path.join(data, "hosts.json")
        try:
            os.chmod(data, 0o700)
            for f in ("hosts.json", "auth.json"):
                if os.path.exists(os.path.join(data, f)):
                    os.chmod(os.path.join(data, f), 0o600)
        except OSError:
            pass
        self.remotes = {}
        self.lock = threading.Lock()
        self.pins = {}
        hosts = []
        try:
            with open(self.config_path) as f:
                cfg = json.load(f)
            hosts = cfg.get("hosts", [])
            self.pins = {k: v for k, v in (cfg.get("pins") or {}).items() if isinstance(v, list)}
        except Exception:
            hosts = (args.hosts or os.environ.get("GPUWATCH_HOSTS", "")).split(",")
            if self.demo_fleet and not any(h.strip() for h in hosts):
                hosts = [t for t, _, _ in DEMO_FLEET]
        self.hosts = []
        self._apply([h for h in (norm_target(x) for x in hosts) if h])

    def _apply(self, hosts):
        with self.lock:
            for t in list(self.remotes):
                if t not in hosts:
                    self.remotes.pop(t).close()
            for t in hosts:
                if t not in self.remotes:
                    self.remotes[t] = Remote(self, t)
            self.hosts = hosts

    def save_hosts(self, hosts, pins=None):
        clean = []
        for h in hosts:
            h = norm_target(str(h))
            if h and h not in clean:
                clean.append(h)
        self._apply(clean[:64])
        if pins is not None:
            new = {}
            for t, lst in pins.items():
                t = norm_target(str(t))
                if t in self.hosts and isinstance(lst, list):
                    new[t] = [{"name": re.sub(r"[^\w .:+()/-]", "", str(x.get("name", "")))[:40],
                               "url": str(x.get("url", ""))[:200], "key": str(x.get("key", ""))[:300]}
                              for x in lst[:8] if isinstance(x, dict) and LOCAL_URL_RE.match(str(x.get("url", "")))]
            changed = [t for t in set(new) | set(self.pins) if new.get(t) != self.pins.get(t)]
            self.pins = {t: v for t, v in new.items() if v}
            for t in changed:
                if t in self.remotes:
                    self.remotes[t].restart()
        self.pins = {t: v for t, v in self.pins.items() if t in self.hosts}
        try:
            fd = os.open(self.config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({"hosts": self.hosts, "pins": self.pins}, f, indent=2)
            os.chmod(self.config_path, 0o600)
        except Exception as e:
            sys.stderr.write("gpuwatch: could not save %s: %s\n" % (self.config_path, e))
        return self.hosts

    def snapshot(self):
        return {"kind": "hub", "hostname": self.hostname, "version": VERSION, "gpus": [], "procs": [], "host": {}}

    def history(self):
        return {"now": time.time(), "gpus": {}}

    def config(self):
        # keys are write-only: the page sees that a key is set, never the key itself
        pins = {t: [{"name": x["name"], "url": x["url"], "has_key": bool(x.get("key"))} for x in v]
                for t, v in self.pins.items()}
        return {"mode": "hub", "hosts": self.hosts, "self": self.hostname, "version": VERSION,
                "pubkey": self.pubkey, "ssh_user": self.ssh_user, "pins": pins,
                "api_token": self.auth.api_token, "hub_ip": self.hub_ip}

    def snapshots(self):
        out = []
        with self.lock:
            remotes = [(t, self.remotes[t]) for t in self.hosts if t in self.remotes]
        for t, r in remotes:
            with r.lock:
                out.append((t, None if r.err else r.snap, r.err))
        return out

    def proxy(self, target, sub):
        r = self.remotes.get(norm_target(target))
        if not r:
            return 403, {"error": "host not in saved list"}
        with r.lock:
            if sub == "history":
                return 200, hist_json(r.hist)
            if r.err:
                return (503 if r.err == "connecting" else 502), {"error": r.err}
            return 200, r.snap


# ----------------------------------------------------------------------------- authentication

class Auth:
    """Password login (PBKDF2 hash on disk), in-memory sessions, and a read-only API token."""
    SESSION_DAYS = 30

    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "auth.json")
        self.lock = threading.Lock()
        self.fail_lock = threading.Lock()
        self.fails = 0
        self.sessions = {}
        cfg = {}
        try:
            with open(self.path) as f:
                cfg = json.load(f)
        except Exception:
            pass
        env_pw = os.environ.get("GPUWATCH_PASSWORD", "")
        if env_pw:
            if not (cfg.get("pw") and self._verify(env_pw, cfg["pw"])):
                cfg["pw"] = self._hash(env_pw)
        elif not cfg.get("pw"):
            pw = secrets.token_urlsafe(18)
            cfg["pw"] = self._hash(pw)
            print("=" * 72, flush=True)
            print("gpuwatch: generated login password (shown once):  %s" % pw, flush=True)
            print("set GPUWATCH_PASSWORD in the compose file to choose your own", flush=True)
            print("=" * 72, flush=True)
        env_tok = os.environ.get("GPUWATCH_API_TOKEN", "")
        cfg["api_token"] = env_tok or cfg.get("api_token") or secrets.token_urlsafe(24)
        self.api_token = cfg["api_token"]
        self.pw = cfg["pw"]
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(cfg, f)
            os.chmod(self.path, 0o600)
        except Exception as e:
            sys.stderr.write("gpuwatch: could not save %s: %s\n" % (self.path, e))

    @staticmethod
    def _hash(pw, salt=None, it=310000):
        salt = salt or secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it)
        return "pbkdf2_sha256$%d$%s$%s" % (it, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())

    @staticmethod
    def _verify(pw, stored):
        try:
            algo, it, salt, dk = stored.split("$")
            calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
            return hmac.compare_digest(calc, base64.b64decode(dk))
        except Exception:
            return False

    def login(self, pw):
        ok = bool(pw) and len(pw) <= 256 and self._verify(pw, self.pw)
        if not ok:
            with self.fail_lock:          # serialised slow-down: online guessing is impractical
                self.fails += 1
                time.sleep(1.0 if self.fails < 20 else 5.0)
            return None
        self.fails = 0
        tok = secrets.token_urlsafe(32)
        with self.lock:
            now = time.time()
            self.sessions = {k: v for k, v in self.sessions.items() if v > now}
            self.sessions[tok] = now + self.SESSION_DAYS * 86400
        return tok

    def valid(self, tok):
        if not tok:
            return False
        with self.lock:
            exp = self.sessions.get(tok)
        return bool(exp and exp > time.time())

    def logout(self, tok):
        with self.lock:
            self.sessions.pop(tok, None)

    def token_ok(self, header):
        if not header or not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].strip().encode(), self.api_token.encode())


LOGIN_PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>gpuwatch · sign in</title><style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0c0e;color:#e4e4e4;
font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
form{background:#141a21;border:1px solid #2a3139;border-left:4px solid #3fdc5d;border-radius:8px;padding:26px 28px;width:320px}
h1{font-size:16px;margin:0 0 16px;color:#3fdc5d}input{width:100%;box-sizing:border-box;font:inherit;color:#e4e4e4;background:#0d1013;
border:1px solid #2c333b;border-radius:4px;padding:8px}button{margin-top:12px;width:100%;font:inherit;padding:8px;background:#1d9a2c;
color:#000;border:0;border-radius:4px;cursor:pointer}.e{color:#ff5f56;margin-top:10px;font-size:12px}</style></head>
<body><form method="post" action="/login"><h1>gpuwatch</h1>
<input type="password" name="password" placeholder="password" autofocus autocomplete="current-password">
<button type="submit">Sign in</button>{{ERR}}</form></body></html>"""


# ----------------------------------------------------------------------------- Prometheus / Homepage

def _lbl(**kw):
    return "{" + ",".join('%s="%s"' % (k, str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " "))
                          for k, v in kw.items()) + "}"


def prometheus(snaps):
    lines = []
    def g(name, help_, rows):
        lines.append("# HELP gpuwatch_%s %s" % (name, help_))
        lines.append("# TYPE gpuwatch_%s gauge" % name)
        for labels, v in rows:
            if v is not None:
                lines.append("gpuwatch_%s%s %s" % (name, labels, float(v)))
    up, util, mu, mt, pw, tp, hc, hm, hmt, sr, sq, st = ([] for _ in range(12))
    for target, snap, err in snaps:
        host = (snap or {}).get("hostname") or target
        up.append((_lbl(target=target, host=host), 0 if snap is None else 1))
        if not snap:
            continue
        for gp in snap.get("gpus") or []:
            L = _lbl(target=target, host=host, gpu=gp.get("index"), name=gp.get("name"))
            util.append((L, gp.get("util"))); mu.append((L, gp.get("mem_used"))); mt.append((L, gp.get("mem_total")))
            pw.append((L, gp.get("power"))); tp.append((L, gp.get("temp")))
        ho = snap.get("host") or {}
        L = _lbl(target=target, host=host)
        hc.append((L, ho.get("cpu"))); hm.append((L, ho.get("mem_used"))); hmt.append((L, ho.get("mem_total")))
        for sv in snap.get("services") or []:
            L = _lbl(target=target, host=host, service=sv.get("name"), kind=sv.get("kind"), port=sv.get("port"),
                     model=(sv.get("models") or [""])[0])
            sr.append((L, sv.get("running"))); sq.append((L, sv.get("queued"))); st.append((L, sv.get("tps")))
    g("up", "1 if the machine is reporting", up)
    g("gpu_utilization_percent", "GPU utilization", util)
    g("gpu_memory_used_bytes", "GPU memory used (Apple: GPU-allocated)", mu)
    g("gpu_memory_total_bytes", "GPU memory total (Apple: wired limit)", mt)
    g("gpu_power_watts", "GPU power draw", pw)
    g("gpu_temperature_celsius", "GPU temperature", tp)
    g("host_cpu_percent", "Host CPU", hc)
    g("host_memory_used_bytes", "Host RAM used", hm)
    g("host_memory_total_bytes", "Host RAM total", hmt)
    g("service_requests_running", "Requests running in a detected model server", sr)
    g("service_requests_queued", "Requests waiting in a detected model server", sq)
    g("service_tokens_per_second", "Generation tokens per second", st)
    return ("\n".join(lines) + "\n").encode()


def summary_one(target, snap, err):
    if not snap:
        return {"target": target, "status": "offline", "error": err}
    gpus = snap.get("gpus") or []
    used = sum(x.get("mem_used") or 0 for x in gpus)
    tot = sum(x.get("mem_total") or 0 for x in gpus)
    utils = [x.get("util") for x in gpus if x.get("util") is not None]
    pows = [x.get("power") for x in gpus if x.get("power") is not None]
    temps = [x.get("temp") for x in gpus if x.get("temp") is not None]
    svcs = snap.get("services") or []
    first = svcs[0] if svcs else {}
    return {
        "target": target, "name": snap.get("hostname"), "status": "online", "gpus": len(gpus),
        "gpu_util": round(sum(utils) / len(utils)) if utils else None,
        "gpu_util_max": round(max(utils)) if utils else None,
        "mem_used_gb": round(used / GiB, 1), "mem_total_gb": round(tot / GiB, 1),
        "mem_free_gb": round(max(0, tot - used) / GiB, 1), "mem_percent": round(100.0 * used / tot) if tot else None,
        "power_w": round(sum(pows)) if pows else None, "temp_max_c": round(max(temps)) if temps else None,
        "service": first.get("name"), "model": (first.get("models") or [None])[0],
        "running": sum(s.get("running") or 0 for s in svcs), "queued": sum(s.get("queued") or 0 for s in svcs),
        "tps": round(sum(s.get("tps") or 0 for s in svcs), 1),
    }


def summary_all(snaps):
    each = [summary_one(*x) for x in snaps]
    on = [x for x in each if x["status"] == "online"]
    used = sum(x["mem_used_gb"] for x in on)
    tot = sum(x["mem_total_gb"] for x in on)
    return {"machines": len(each), "online": len(on), "gpus": sum(x["gpus"] for x in on),
            "mem_used_gb": round(used, 1), "mem_total_gb": round(tot, 1), "mem_free_gb": round(tot - used, 1),
            "power_w": sum(x["power_w"] or 0 for x in on), "running": sum(x["running"] for x in on),
            "queued": sum(x["queued"] for x in on), "tps": round(sum(x["tps"] for x in on), 1)}


# ----------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    agent = None
    server_version = "gpuwatch/" + VERSION

    def log_message(self, *a):
        pass

    CSP = ("default-src 'none'; script-src %s; style-src 'unsafe-inline'; img-src 'self' data:; "
           "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    _script_hash = None

    @classmethod
    def script_src(cls):
        """Only the dashboard's own inline script may run: CSP pins its SHA-256 (no 'unsafe-inline')."""
        if cls._script_hash is None:
            try:
                with open(os.path.join(HERE, "dashboard.html"), encoding="utf-8") as f:
                    html = f.read()
                hashes = ["'sha256-%s'" % base64.b64encode(hashlib.sha256(m.encode("utf-8")).digest()).decode()
                          for m in re.findall(r"<script>(.*?)</script>", html, re.S)]
                cls._script_hash = " ".join(hashes) or "'none'"
            except OSError:
                cls._script_hash = "'none'"
        return cls._script_hash

    def _send(self, code, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # agent mode (legacy, LAN only) lets other agents' pages read its stats; the hub allows no cross-origin use
        if not isinstance(self.agent, Hub) and self.command == "GET" and self._path() in ("/stats", "/history"):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", self.CSP % self.script_src())
        if self._https():
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _path(self):
        return urllib.parse.unquote(self.path.split("?")[0])

    def _https(self):
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "gw_session":
                return v
        return ""

    def _authed(self):
        a = self.agent
        return not isinstance(a, Hub) or a.auth.valid(self._cookie())

    def _same_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True                      # not sent by browsers for same-origin GET; POSTs also need X-Gpuwatch
        host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").split(",")[0].strip()
        return urllib.parse.urlsplit(origin).netloc == host

    def do_OPTIONS(self):
        self._send(405, {"error": "method not allowed"})

    def do_GET(self):
        path = self._path()
        a = self.agent
        hub = isinstance(a, Hub)
        if path == "/healthz":
            self._send(200, {"ok": True})
            return
        if hub and path == "/login":
            err = '<div class="e">Wrong password</div>' if "e=1" in self.path else ""
            self._send(200, LOGIN_PAGE.replace("{{ERR}}", err).encode(), "text/html; charset=utf-8")
            return
        # read-only machine endpoints: API token (Prometheus / Homepage) or a signed-in session
        if path == "/metrics" or path.startswith("/api/summary"):
            if hub and not (a.auth.token_ok(self.headers.get("Authorization", "")) or self._authed()):
                self._send(401, {"error": "unauthorized"}, headers={"WWW-Authenticate": "Bearer"})
                return
        elif not self._authed():
            if path in ("/", "/index.html"):
                self._send(303, b"", "text/plain", {"Location": "/login"})
            else:
                self._send(401, {"error": "unauthorized"})
            return
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(HERE, "dashboard.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(404, {"error": "dashboard.html not found next to gpuwatch.py"})
        elif path == "/stats":
            self._send(200, a.snapshot())
        elif path == "/history":
            self._send(200, a.history())
        elif path == "/config":
            self._send(200, a.config())
        elif path.startswith("/proxy/"):
            target, _, sub = path[len("/proxy/"):].rpartition("/")
            if sub not in ("stats", "history"):
                self._send(404, {"error": "unknown endpoint"})
                return
            self._send(*a.proxy(target, sub))
        elif path == "/metrics":
            self._send(200, prometheus(a.snapshots()), "text/plain; version=0.0.4")
        elif path == "/api/summary":
            self._send(200, summary_all(a.snapshots()))
        elif path.startswith("/api/summary/"):
            want = path[len("/api/summary/"):]
            for t, snap, err in a.snapshots():
                if t == want or norm_target(want) == t or ((snap or {}).get("hostname") or "").lower() == want.lower():
                    self._send(200, summary_one(t, snap, err))
                    return
            self._send(404, {"error": "unknown machine"})
        elif path == "/healthz":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self._path()
        a = self.agent
        hub = isinstance(a, Hub)
        if hub and path == "/login":
            n = min(int(self.headers.get("Content-Length") or 0), 4096)
            form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            if not self._same_origin():
                self._send(403, {"error": "bad origin"})
                return
            tok = a.auth.login((form.get("password") or [""])[0])
            if not tok:
                self._send(303, b"", "text/plain", {"Location": "/login?e=1"})
                return
            cookie = "gw_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s" % (
                tok, Auth.SESSION_DAYS * 86400, "; Secure" if self._https() else "")
            self._send(303, b"", "text/plain", {"Location": "/", "Set-Cookie": cookie})
            return
        if hub and path == "/logout":
            if self.headers.get("X-Gpuwatch") == "1" and self._same_origin():
                a.auth.logout(self._cookie())
            self._send(200, {"ok": True},
                       headers={"Set-Cookie": "gw_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
            return
        if path != "/config":
            self._send(404, {"error": "not found"})
            return
        if not hub and not getattr(a.args, "allow_config", False):
            self._send(403, {"error": "editing the host list is disabled in agent mode (start with --allow-config)"})
            return
        # changes need: a valid session, our custom header (forces CORS preflight, which we never allow) and same origin
        if not self._authed() or self.headers.get("X-Gpuwatch") != "1" or not self._same_origin():
            self._send(403, {"error": "forbidden"})
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
            hosts = body.get("hosts")
            pins = body.get("pins")
            if not isinstance(hosts, list):
                raise ValueError("hosts must be a list")
            if pins is not None and not isinstance(pins, dict):
                raise ValueError("pins must be an object")
        except Exception as e:
            self._send(400, {"error": str(e)})
            return
        if isinstance(self.agent, Hub) and pins is not None:
            # a pin sent without a key keeps the key already saved for that URL
            for t, lst in pins.items():
                old = {x["url"]: x.get("key", "") for x in self.agent.pins.get(norm_target(t), [])}
                for x in lst if isinstance(lst, list) else []:
                    if isinstance(x, dict) and not x.get("key"):
                        x["key"] = old.get(x.get("url"), "")
            self.agent.save_hosts(hosts, pins)
        else:
            self.agent.save_hosts(hosts)
        self._send(200, self.agent.config())


def stream(args):
    """Remote side of hub mode: print one JSON snapshot per line until the pipe closes."""
    demo = args.demo or os.environ.get("GPUWATCH_DEMO")
    source = Demo(demo) if demo else detect()
    name = args.name or os.environ.get("GPUWATCH_NAME") or socket.gethostname().split(".")[0]
    try:
        pins = json.loads(PINS_JSON)
    except ValueError:
        pins = []
    services = None if demo else Services(pins)
    while True:
        t0 = time.time()
        try:
            snap = source.collect()
        except Exception as e:
            snap = {"kind": "error", "error": str(e), "gpus": [], "procs": [], "host": {}}
        snap.update(hostname=name, version=VERSION, interval=args.interval)
        if services:
            snap["services"] = services.snapshot()
            snap["discovery"] = services.diag()
        elif demo:
            snap["services"] = demo_services(demo)
        try:
            sys.stdout.write(json.dumps(snap) + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, OSError):
            os._exit(0)
        time.sleep(max(0.05, args.interval - (time.time() - t0)))


def main():
    ap = argparse.ArgumentParser(description="gpuwatch agent / hub")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds between samples")
    ap.add_argument("--hosts", default="", help="comma list the dashboard shows (first run)")
    ap.add_argument("--name", default="", help="display name (default: hostname)")
    ap.add_argument("--state-dir", default="", help="where hosts.json (and the hub's SSH key) live")
    ap.add_argument("--hub", action="store_true", help="agentless hub: collect from hosts over SSH")
    ap.add_argument("--ssh-user", default="", help="hub: default SSH user (or GPUWATCH_SSH_USER)")
    ap.add_argument("--allow-config", action="store_true", help="agent mode: allow editing the host list from the page")
    ap.add_argument("--stream", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--demo", choices=["nvidia4", "nvidia1", "apple", "applemax", "invoke", "nas"],
                    help="serve fake data for testing")
    args = ap.parse_args()

    if args.stream:
        stream(args)
        return

    Handler.agent = Hub(args) if args.hub else Agent(args)
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    srv.daemon_threads = True
    kind = "hub" if args.hub else type(Handler.agent.source).__name__
    print("gpuwatch %s (%s) on http://%s:%d" % (VERSION, kind, args.bind, args.port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
