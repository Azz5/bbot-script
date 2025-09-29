#!/usr/bin/env python3
import argparse
import subprocess
import time
from datetime import datetime
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor
import threading
import math
import os
 
def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)
 
def build_base_cmd(domain, es_api, username=None, password=None):
    # Kept exactly as you had it — ignoring passed username/password
    cmd = [
        "sudo", "/home/kali/.local/bin/bbot",
        "-t", domain,
        "-om", "http",
        "-c", f"modules.http.url={es_api}",
        "modules.http.siem_friendly=true",
        "modules.http.username=user1",
        "modules.http.password=password",
        "--yes"
    ]
    return cmd
 
SCANS = [
    {"name": "web_probe",      "args": ["-p", "web-basic"],        "period": 900},
    {"name": "port_scan",      "args": ["-p", "subdomain-enum", "-m", "portscan"], "period": 1800},
]
 
_stdout_lock = threading.Lock()
_stderr_lock = threading.Lock()
 
def run_scan(cmd):
    start = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    end = time.time()
    ok = proc.returncode == 0
    return ok, end - start, proc
 
def load_domains_from_file(path):
    domains = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains
 
def main():
    p = argparse.ArgumentParser(description="Run multiple BBOT scans across multiple domains and send results to Elasticsearch via HTTP output module.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--domains-file", "-f", help="File containing domains (one per line). Lines starting with # are ignored.")
    group.add_argument("domains", nargs="*", help="Domains to scan (e.g. example.com). Use either positional domains or --domains-file.")
    p.add_argument("api", help="Elasticsearch document API URL, e.g. https://es:9200/bbot/_doc")
    p.add_argument("--username", help="(ignored, kept for compatibility)")
    p.add_argument("--password", help="(ignored, kept for compatibility)")
    p.add_argument("--max-workers", type=int, default=0, help="Maximum threadpool workers (default: min(32, number of scheduled tasks)).")
    args = p.parse_args()
 
    if args.domains_file:
        if not os.path.isfile(args.domains_file):
            log(f"ERROR: domains file not found: {args.domains_file}")
            sys.exit(2)
        domains = load_domains_from_file(args.domains_file)
    else:
        domains = args.domains
 
    if not domains:
        log("ERROR: no domains provided.")
        sys.exit(2)
 
    # build schedule with an entry per (domain, scan)
    now = time.time()
    schedule = []
    for domain in domains:
        for s in SCANS:
            schedule.append({
                "domain": domain,
                "name": s["name"],
                "args": s["args"],
                "period": s["period"],
                "next": now,
                "running": False,
            })
 
    # sensible default for max_workers: cap to avoid overwhelming system
    total_tasks = len(schedule)
    if args.max_workers and args.max_workers > 0:
        max_workers = args.max_workers
    else:
        max_workers = min(32, max(1, total_tasks))
 
    executor = ThreadPoolExecutor(max_workers=max_workers)
    stop_event = threading.Event()
 
    def launch_scan(s):
        # construct command specific to domain
        cmd = build_base_cmd(s["domain"], args.api, args.username, args.password) + s["args"]
        log(f"Running {s['domain']}:{s['name']}: {shlex.join(cmd)}")
        future = executor.submit(run_scan, cmd)
 
        def on_done(fut):
            try:
                ok, duration, proc = fut.result()
            except FileNotFoundError:
                log("ERROR: 'bbot' not found on PATH. Exiting.")
                stop_event.set()
                return
            except Exception as e:
                log(f"ERROR running {s['domain']}:{s['name']}: {e}")
                s["next"] = time.time() + s["period"]
                s["running"] = False
                return
 
            if proc.stdout:
                with _stdout_lock:
                    sys.stdout.write(proc.stdout)
                    sys.stdout.flush()
            if proc.stderr:
                with _stderr_lock:
                    sys.stderr.write(proc.stderr)
                    sys.stderr.flush()
 
            if not ok:
                log(f"{s['domain']}:{s['name']} FAILED in {duration:.1f}s (returncode {proc.returncode})")
            else:
                log(f"{s['domain']}:{s['name']} completed in {duration:.1f}s")
 
            s["next"] = time.time() + s["period"]
            s["running"] = False
 
        s["running"] = True
        s["next"] = math.inf
        future.add_done_callback(on_done)
 
    log(f"Starting multi-domain multi-period scheduler (parallel). Domains: {', '.join(domains)}. Press Ctrl-C to stop.")
    try:
        while not stop_event.is_set():
            now = time.time()
            due = [s for s in schedule if (not s["running"]) and (s["next"] <= now)]
            # prioritize older next times first
            for s in sorted(due, key=lambda x: x["next"]):
                launch_scan(s)
 
            next_times = [s["next"] for s in schedule if not s["running"]]
            if next_times:
                sleep_for = max(min(next_times) - now, 0.2)
            else:
                sleep_for = 0.5
            time.sleep(sleep_for)
    except KeyboardInterrupt:
        log("Exiting.")
    finally:
        # don't wait for running tasks to finish; preserve prior behavior
        executor.shutdown(wait=False)
 
if __name__ == "__main__":
    main()
