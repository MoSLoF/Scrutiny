#!/usr/bin/env python3
"""
monitor.py - Scrutiny behavioral analysis and anomaly detection engine

Phase 6: Full CLI mode, JSON baseline library, auto-diff, presentation output.

Usage:
  python3 monitor.py                          # interactive (tkinter file picker)
  python3 monitor.py --baseline <jsonl>       # save as named baseline
  python3 monitor.py --compare <jsonl>        # auto-diff against stored baseline
  python3 monitor.py --compare <jsonl> --baseline-file <jsonl>  # explicit diff
  python3 monitor.py --list-baselines         # show stored baselines
  python3 monitor.py --summary <jsonl>        # single-file summary only

Risk Tiers:
  CRITICAL (10): execve, connect, sendto, ptrace, init_module, ...
  HIGH     ( 7): socket, access, chmod, kill, setuid, mount, ...
  MEDIUM   ( 3): open, openat, read, write, fork, clone, bind, ...
  LOW      ( 1): everything else

Part of the Scrutiny project - HoneyBadger Vanguard fork.
"""

import os
import re
import sys
import json
import argparse
import datetime
from collections import Counter
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR    = Path(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT     = SCRIPT_DIR.parent
LOGS_DIR      = REPO_ROOT / 'logs'
BASELINE_DIR  = LOGS_DIR / 'baselines'
BASELINE_JSON = BASELINE_DIR / 'baseline_library.json'

# ---------------------------------------------------------------------------
# ANSI color helpers (degrade gracefully on Windows without colorama)
# ---------------------------------------------------------------------------
def _supports_color():
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

COLOR = _supports_color()

def red(s):    return f"\033[91m{s}\033[0m" if COLOR else s
def yellow(s): return f"\033[93m{s}\033[0m" if COLOR else s
def cyan(s):   return f"\033[96m{s}\033[0m" if COLOR else s
def green(s):  return f"\033[92m{s}\033[0m" if COLOR else s
def bold(s):   return f"\033[1m{s}\033[0m"  if COLOR else s
def gray(s):   return f"\033[90m{s}\033[0m" if COLOR else s

TIER_COLOR = {
    'CRITICAL': red,
    'HIGH':     yellow,
    'MEDIUM':   cyan,
    'LOW':      gray,
}

TIER_TAG = {
    'CRITICAL': '[!!!]',
    'HIGH':     '[ ! ]',
    'MEDIUM':   '[ ~ ]',
    'LOW':      '[   ]',
}

# ---------------------------------------------------------------------------
# Syscall risk scoring table
# ---------------------------------------------------------------------------
RISK_TABLE = {
    'execve':            ('CRITICAL', 10),
    'execveat':          ('CRITICAL', 10),
    'connect':           ('CRITICAL', 10),
    'sendto':            ('CRITICAL', 10),
    'sendmsg':           ('CRITICAL', 10),
    'sendmmsg':          ('CRITICAL', 10),
    'ptrace':            ('CRITICAL', 10),
    'init_module':       ('CRITICAL', 10),
    'finit_module':      ('CRITICAL', 10),
    'delete_module':     ('CRITICAL', 10),
    'kexec_load':        ('CRITICAL', 10),
    'kexec_file_load':   ('CRITICAL', 10),
    'bpf':               ('CRITICAL', 10),
    'process_vm_writev': ('CRITICAL', 10),

    'socket':            ('HIGH', 7),
    'access':            ('HIGH', 7),
    'faccessat':         ('HIGH', 7),
    'chmod':             ('HIGH', 7),
    'fchmod':            ('HIGH', 7),
    'fchmodat':          ('HIGH', 7),
    'chown':             ('HIGH', 7),
    'fchown':            ('HIGH', 7),
    'lchown':            ('HIGH', 7),
    'fchownat':          ('HIGH', 7),
    'kill':              ('HIGH', 7),
    'tkill':             ('HIGH', 7),
    'tgkill':            ('HIGH', 7),
    'setuid':            ('HIGH', 7),
    'setgid':            ('HIGH', 7),
    'setreuid':          ('HIGH', 7),
    'setregid':          ('HIGH', 7),
    'setresuid':         ('HIGH', 7),
    'setresgid':         ('HIGH', 7),
    'setfsuid':          ('HIGH', 7),
    'setfsgid':          ('HIGH', 7),
    'capset':            ('HIGH', 7),
    'mount':             ('HIGH', 7),
    'umount2':           ('HIGH', 7),
    'chroot':            ('HIGH', 7),
    'pivot_root':        ('HIGH', 7),
    'prctl':             ('HIGH', 7),
    'seccomp':           ('HIGH', 7),

    'open':              ('MEDIUM', 3),
    'openat':            ('MEDIUM', 3),
    'openat2':           ('MEDIUM', 3),
    'read':              ('MEDIUM', 3),
    'write':             ('MEDIUM', 3),
    'unlink':            ('MEDIUM', 3),
    'unlinkat':          ('MEDIUM', 3),
    'rename':            ('MEDIUM', 3),
    'renameat':          ('MEDIUM', 3),
    'renameat2':         ('MEDIUM', 3),
    'fork':              ('MEDIUM', 3),
    'vfork':             ('MEDIUM', 3),
    'clone':             ('MEDIUM', 3),
    'bind':              ('MEDIUM', 3),
    'listen':            ('MEDIUM', 3),
    'accept':            ('MEDIUM', 3),
    'accept4':           ('MEDIUM', 3),
}

# Authoritative Linux x86_64 syscall number -> name mapping
SYSCALL_NAMES = {
    0: 'read',          1: 'write',         2: 'open',
    3: 'close',         4: 'stat',          5: 'fstat',
    6: 'lstat',         7: 'poll',          8: 'lseek',
    9: 'mmap',          10: 'mprotect',     11: 'munmap',
    12: 'brk',          13: 'rt_sigaction', 14: 'rt_sigprocmask',
    15: 'rt_sigreturn', 16: 'ioctl',        17: 'pread64',
    18: 'pwrite64',     19: 'readv',        20: 'writev',
    21: 'access',       22: 'pipe',         23: 'select',
    24: 'sched_yield',  25: 'mremap',       26: 'msync',
    27: 'mincore',      28: 'madvise',      29: 'shmget',
    30: 'shmat',        31: 'shmctl',       32: 'dup',
    33: 'dup2',         34: 'pause',        35: 'nanosleep',
    36: 'getitimer',    37: 'alarm',        38: 'setitimer',
    39: 'getpid',       40: 'sendfile',     41: 'socket',
    42: 'connect',      43: 'accept',       44: 'sendto',
    45: 'recvfrom',     46: 'sendmsg',      47: 'recvmsg',
    48: 'shutdown',     49: 'bind',         50: 'listen',
    51: 'getsockname',  52: 'getpeername',  53: 'socketpair',
    54: 'setsockopt',   55: 'getsockopt',   56: 'clone',
    57: 'fork',         58: 'vfork',        59: 'execve',
    60: 'exit',         61: 'wait4',        62: 'kill',
    63: 'uname',        64: 'semget',       65: 'semop',
    66: 'semctl',       67: 'shmdt',        68: 'msgget',
    69: 'msgsnd',       70: 'msgrcv',       71: 'msgctl',
    72: 'fcntl',        73: 'flock',        74: 'fsync',
    75: 'fdatasync',    76: 'truncate',     77: 'ftruncate',
    78: 'getdents',     79: 'getcwd',       80: 'chdir',
    81: 'fchdir',       82: 'rename',       83: 'mkdir',
    84: 'rmdir',        85: 'creat',        86: 'link',
    87: 'unlink',       88: 'symlink',      89: 'readlink',
    90: 'chmod',        91: 'fchmod',       92: 'chown',
    93: 'fchown',       94: 'lchown',       95: 'umask',
    96: 'gettimeofday', 97: 'getrlimit',    98: 'getrusage',
    99: 'sysinfo',      100: 'times',       101: 'ptrace',
    102: 'getuid',      103: 'syslog',      104: 'getgid',
    105: 'setuid',      106: 'setgid',      107: 'geteuid',
    108: 'getegid',     109: 'setpgid',     110: 'getppid',
    111: 'getpgrp',     112: 'setsid',      113: 'setreuid',
    114: 'setregid',    115: 'getgroups',   116: 'setgroups',
    117: 'setresuid',   118: 'getresuid',   119: 'setresgid',
    120: 'getresgid',   121: 'getpgid',     122: 'setfsuid',
    123: 'setfsgid',    124: 'getsid',      125: 'capget',
    126: 'capset',      127: 'rt_sigpending', 128: 'rt_sigtimedwait',
    129: 'rt_sigqueueinfo', 130: 'rt_sigsuspend', 131: 'sigaltstack',
    132: 'utime',       133: 'mknod',       134: 'uselib',
    135: 'personality', 136: 'ustat',       137: 'statfs',
    138: 'fstatfs',     139: 'sysfs',       140: 'getpriority',
    141: 'setpriority', 142: 'sched_setparam', 143: 'sched_getparam',
    144: 'sched_setscheduler', 145: 'sched_getscheduler',
    146: 'sched_get_priority_max', 147: 'sched_get_priority_min',
    148: 'sched_rr_get_interval',
    149: 'mlock',       150: 'munlock',     151: 'mlockall',
    152: 'munlockall',  153: 'vhangup',     154: 'modify_ldt',
    155: 'pivot_root',  156: '_sysctl',     157: 'prctl',
    158: 'arch_prctl',  159: 'adjtimex',    160: 'setrlimit',
    161: 'chroot',      162: 'sync',        163: 'acct',
    164: 'settimeofday', 165: 'mount',      166: 'umount2',
    167: 'swapon',      168: 'swapoff',     169: 'reboot',
    170: 'sethostname', 171: 'setdomainname', 172: 'iopl',
    173: 'ioperm',      174: 'create_module', 175: 'init_module',
    176: 'delete_module', 177: 'get_kernel_syms', 178: 'query_module',
    179: 'quotactl',    180: 'nfsservctl',  181: 'getpmsg',
    182: 'putpmsg',     183: 'afs_syscall', 184: 'tuxcall',
    185: 'security',    186: 'gettid',      187: 'readahead',
    188: 'setxattr',    189: 'lsetxattr',   190: 'fsetxattr',
    191: 'getxattr',    192: 'lgetxattr',   193: 'fgetxattr',
    194: 'listxattr',   195: 'llistxattr',  196: 'flistxattr',
    197: 'removexattr', 198: 'lremovexattr', 199: 'fremovexattr',
    200: 'tkill',       201: 'time',        202: 'futex',
    203: 'sched_setaffinity', 204: 'sched_getaffinity',
    205: 'set_thread_area', 206: 'io_setup', 207: 'io_destroy',
    208: 'io_getevents', 209: 'io_submit',  210: 'io_cancel',
    211: 'get_thread_area', 212: 'lookup_dcookie', 213: 'epoll_create',
    214: 'epoll_ctl_old', 215: 'epoll_wait_old', 216: 'remap_file_pages',
    217: 'getdents64',  218: 'set_tid_address', 219: 'restart_syscall',
    220: 'semtimedop',  221: 'fadvise64',   222: 'timer_create',
    223: 'timer_settime', 224: 'timer_gettime', 225: 'timer_getoverrun',
    226: 'timer_delete', 227: 'clock_settime', 228: 'clock_gettime',
    229: 'clock_getres', 230: 'clock_nanosleep', 231: 'exit_group',
    232: 'epoll_wait',  233: 'epoll_ctl',   234: 'tgkill',
    235: 'utimes',      236: 'vserver',     237: 'mbind',
    238: 'set_mempolicy', 239: 'get_mempolicy', 240: 'mq_open',
    241: 'mq_unlink',   242: 'mq_timedsend', 243: 'mq_timedreceive',
    244: 'mq_notify',   245: 'mq_getsetattr', 246: 'kexec_load',
    247: 'waitid',      248: 'add_key',     249: 'request_key',
    250: 'keyctl',      251: 'ioprio_set',  252: 'ioprio_get',
    253: 'inotify_init', 254: 'inotify_add_watch', 255: 'inotify_rm_watch',
    256: 'migrate_pages', 257: 'openat',    258: 'mkdirat',
    259: 'mknodat',     260: 'fchownat',    261: 'futimesat',
    262: 'newfstatat',  263: 'unlinkat',    264: 'renameat',
    265: 'linkat',      266: 'symlinkat',   267: 'readlinkat',
    268: 'fchmodat',    269: 'faccessat',   270: 'pselect6',
    271: 'ppoll',       272: 'unshare',     273: 'set_robust_list',
    274: 'get_robust_list', 275: 'splice',  276: 'tee',
    277: 'sync_file_range', 278: 'vmsplice', 279: 'move_pages',
    280: 'utimensat',   281: 'epoll_pwait', 282: 'signalfd',
    283: 'timerfd_create', 284: 'eventfd',  285: 'fallocate',
    286: 'timerfd_settime', 287: 'timerfd_gettime', 288: 'accept4',
    289: 'signalfd4',   290: 'eventfd2',    291: 'epoll_create1',
    292: 'dup3',        293: 'pipe2',       294: 'inotify_init1',
    295: 'preadv',      296: 'pwritev',     297: 'rt_tgsigqueueinfo',
    298: 'perf_event_open', 299: 'recvmmsg', 300: 'fanotify_init',
    301: 'fanotify_mark', 302: 'prlimit64', 303: 'name_to_handle_at',
    304: 'open_by_handle_at', 305: 'clock_adjtime', 306: 'syncfs',
    307: 'sendmmsg',    308: 'setns',       309: 'getcpu',
    310: 'process_vm_readv', 311: 'process_vm_writev', 312: 'kcmp',
    313: 'finit_module', 314: 'sched_setattr', 315: 'sched_getattr',
    316: 'renameat2',   317: 'seccomp',     318: 'getrandom',
    319: 'memfd_create', 320: 'kexec_file_load', 321: 'bpf',
    322: 'execveat',    323: 'userfaultfd', 324: 'membarrier',
    325: 'mlock2',      326: 'copy_file_range', 327: 'preadv2',
    328: 'pwritev2',    329: 'pkey_mprotect', 330: 'pkey_alloc',
    331: 'pkey_free',   332: 'statx',       333: 'io_pgetevents',
    334: 'rseq',        424: 'pidfd_send_signal', 434: 'pidfd_open',
    438: 'pidfd_getfd',
}

# ---------------------------------------------------------------------------
# Core data functions
# ---------------------------------------------------------------------------

def get_risk(syscall_name):
    return RISK_TABLE.get(syscall_name, ('LOW', 1))


def parse_jsonl(path):
    """Parse a .jsonl log file. Returns list of event dicts."""
    events = []
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
    return events


def parse_log(path):
    """Parse a .log file (legacy plaintext). Returns Counter of syscall nums."""
    syscall_pattern = r"Syscall: (\d+) \("
    counts = Counter()
    try:
        with open(path, 'r') as f:
            for line in f:
                m = re.search(syscall_pattern, line)
                if m:
                    counts[int(m.group(1))] += 1
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
    return counts


def events_to_counts(events):
    """Convert event list to Counter keyed by syscall_name."""
    counts = Counter()
    for e in events:
        name = e.get('syscall_name', 'unknown')
        counts[name] += 1
    return counts


def compute_threat_score(name_counts):
    """Compute weighted threat score from name-keyed Counter."""
    total_score = 0
    tier_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    tier_scores = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for name, count in name_counts.items():
        tier, score = get_risk(name)
        weighted = count * score
        total_score += weighted
        tier_counts[tier] += count
        tier_scores[tier] += weighted
    return total_score, tier_counts, tier_scores


def compare_runs(baseline_counts, target_counts):
    """
    Compare baseline vs target (both name-keyed Counters).
    Returns list of anomaly dicts sorted by risk score descending.
    """
    anomalies = []
    total_b = sum(baseline_counts.values()) or 1
    total_t = sum(target_counts.values()) or 1
    all_names = set(baseline_counts) | set(target_counts)

    for name in sorted(all_names):
        b = baseline_counts.get(name, 0)
        t = target_counts.get(name, 0)
        b_freq = b / total_b
        t_freq = t / total_t
        tier, score = get_risk(name)

        if b == 0 and t > 0:
            anomalies.append({
                'syscall': name, 'tier': tier, 'score': score,
                'type': 'NEW',
                'desc': f"NEW in target ({t}x, absent in baseline)",
                'baseline_count': b, 'target_count': t,
            })
        elif b_freq > 0 and t_freq > 2 * b_freq and t > 1:
            ratio = t_freq / b_freq
            anomalies.append({
                'syscall': name, 'tier': tier, 'score': score,
                'type': 'SPIKE',
                'desc': f"FREQUENCY spike {ratio:.1f}x (baseline={b}, target={t})",
                'baseline_count': b, 'target_count': t,
            })

    anomalies.sort(key=lambda x: x['score'], reverse=True)
    return anomalies


# ---------------------------------------------------------------------------
# Baseline library (JSON store)
# ---------------------------------------------------------------------------

def load_library():
    if BASELINE_JSON.exists():
        try:
            with open(BASELINE_JSON) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_library(lib):
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    with open(BASELINE_JSON, 'w') as f:
        json.dump(lib, f, indent=2)


def store_baseline(target_name, jsonl_path):
    """Parse a JSONL and store its syscall counts as a named baseline."""
    events = parse_jsonl(jsonl_path)
    if not events:
        print(f"ERROR: No events parsed from {jsonl_path}", file=sys.stderr)
        return False
    counts = events_to_counts(events)
    lib = load_library()
    ts = datetime.datetime.now().isoformat(timespec='seconds')
    lib[target_name] = {
        'stored_at': ts,
        'source': str(jsonl_path),
        'total_events': len(events),
        'syscall_counts': dict(counts),
    }
    save_library(lib)
    print(green(f"[+] Baseline '{target_name}' stored ({len(events)} events, {ts})"))
    return True


def load_baseline_counts(target_name):
    """Return name-keyed Counter for a stored baseline, or None."""
    lib = load_library()
    entry = lib.get(target_name)
    if not entry:
        return None
    return Counter(entry['syscall_counts'])


def list_baselines():
    lib = load_library()
    if not lib:
        print("No baselines stored.")
        return
    SEP = '=' * 62
    print(f"\n{SEP}")
    print(bold("  Stored Baselines"))
    print(SEP)
    for name, entry in lib.items():
        print(f"  {bold(name)}")
        print(f"    Stored : {entry.get('stored_at','?')}")
        print(f"    Events : {entry.get('total_events','?')}")
        print(f"    Source : {entry.get('source','?')}")
    print(SEP)


# ---------------------------------------------------------------------------
# Display functions
# ---------------------------------------------------------------------------
SEP62 = '=' * 62
SEP62d = '-' * 62

def print_banner():
    print(f"\n{bold(SEP62)}")
    print(bold("  Scrutiny Monitor - Behavioral Analysis Engine"))
    print(bold("  HoneyBadger Vanguard - Phase 6"))
    print(bold(SEP62))


def print_summary(name_counts, label):
    total = sum(name_counts.values()) or 1
    total_score, tier_counts, tier_scores = compute_threat_score(name_counts)

    print(f"\n{SEP62}")
    print(bold(f"  {label}"))
    print(SEP62)
    print(f"  Total events  : {bold(str(total)):>8}")
    print(f"  Threat score  : {bold(str(total_score)):>8}")
    print(f"  Tier counts   : "
          f"{red('CRIT='+ str(tier_counts['CRITICAL']))}  "
          f"{yellow('HIGH='+ str(tier_counts['HIGH']))}  "
          f"{cyan('MED='+ str(tier_counts['MEDIUM']))}  "
          f"{gray('LOW='+ str(tier_counts['LOW']))}")
    print(f"\n  {bold('Syscall'):<28} {'Count':>6}  {'Freq':>7}  {'Tier':<10} {'Pts':>5}")
    print(f"  {SEP62d}")

    for name, count in sorted(name_counts.items(), key=lambda x: x[1], reverse=True)[:25]:
        tier, score = get_risk(name)
        freq = count / total
        col = TIER_COLOR.get(tier, lambda x: x)
        print(f"  {col(f'{name:<26}')}  {count:>6}  {freq:>7.4f}  {tier:<10} {score:>5}")

    if len(name_counts) > 25:
        print(f"  {gray(f'... and {len(name_counts)-25} more syscalls')}")


def print_anomalies(anomalies, baseline_score, target_score, baseline_label, target_label):
    print(f"\n{SEP62}")
    print(bold("  ANOMALY ANALYSIS"))
    print(SEP62)
    print(f"  Baseline : {baseline_label}")
    print(f"  Target   : {target_label}")
    print(f"  Baseline threat score : {baseline_score:,}")
    print(f"  Target threat score   : {target_score:,}")

    delta = target_score - baseline_score
    pct   = (delta / baseline_score * 100) if baseline_score > 0 else 0
    delta_str = f"{delta:+,} ({pct:+.1f}%)"
    delta_col = red(delta_str) if delta > 0 else green(delta_str)
    print(f"  Delta                 : {delta_col}")

    if not anomalies:
        print(f"\n  {green('[CLEAN]')} No significant anomalies detected.")
        print(SEP62)
        return

    crit_anomalies = [a for a in anomalies if a['tier'] == 'CRITICAL']
    print(f"\n  {red(bold(str(len(anomalies)) + ' anomalies detected'))}  "
          f"({red(str(len(crit_anomalies)) + ' CRITICAL')})\n")
    print(f"  {'#':<4} {'Tag':<6} {'Score':>5}  {'Syscall':<24}  Description")
    print(f"  {SEP62d}")

    for i, a in enumerate(anomalies, 1):
        tag = TIER_TAG.get(a['tier'], '     ')
        col = TIER_COLOR.get(a['tier'], lambda x: x)
        print(f"  {i:<4} {col(tag)} {a['score']:>5}  {col(a['syscall']+'  '):<26}  {a['desc']}")

    print(f"\n{SEP62}")

    # VERDICT
    if crit_anomalies:
        print(red(bold("  VERDICT: SUSPICIOUS BEHAVIOR DETECTED")))
        print(red(f"  {len(crit_anomalies)} CRITICAL syscall anomalies present."))
        for a in crit_anomalies:
            print(red(f"    [!!!] {a['syscall']}: {a['desc']}"))
    else:
        print(yellow("  VERDICT: ELEVATED ACTIVITY - review recommended"))
    print(SEP62)


# ---------------------------------------------------------------------------
# File selection helpers
# ---------------------------------------------------------------------------

def select_file_gui(prompt, initial_dir=None):
    if not TKINTER_AVAILABLE:
        return None
    root = tk.Tk()
    root.withdraw()
    path = filedialog.askopenfilename(
        title=prompt,
        initialdir=str(initial_dir) if initial_dir and initial_dir.is_dir()
                   else str(REPO_ROOT),
        filetypes=[("Log files", "*.jsonl *.log"), ("All files", "*.*")]
    )
    root.destroy()
    return Path(path) if path else None


def select_file_cli(prompt, initial_dir=None):
    print(f"\n{prompt}")
    if initial_dir and initial_dir.is_dir():
        # List recent files as a menu
        files = sorted(initial_dir.glob('**/*.jsonl'), key=lambda p: p.stat().st_mtime, reverse=True)[:10]
        if files:
            print("  Recent files:")
            for i, f in enumerate(files, 1):
                print(f"  {i:>2}. {f.relative_to(REPO_ROOT)}")
            print("   0. Enter path manually")
            choice = input("  Select [1-10 or 0]: ").strip()
            try:
                idx = int(choice)
                if 1 <= idx <= len(files):
                    return files[idx - 1]
            except ValueError:
                pass
    path = input("  Enter full path: ").strip()
    p = Path(path)
    return p if p.exists() else None


# ---------------------------------------------------------------------------
# Main modes
# ---------------------------------------------------------------------------

def mode_summary(jsonl_path):
    print_banner()
    events = parse_jsonl(jsonl_path)
    if not events:
        print(f"ERROR: No events in {jsonl_path}", file=sys.stderr)
        sys.exit(1)
    counts = events_to_counts(events)
    print_summary(counts, f"SUMMARY: {Path(jsonl_path).name}")
    print()


def mode_store_baseline(jsonl_path, target_name):
    print_banner()
    if not target_name:
        target_name = Path(jsonl_path).parent.parent.name  # infer from path
    print(f"[*] Storing baseline for '{target_name}' from:\n    {jsonl_path}")
    store_baseline(target_name, jsonl_path)


def mode_compare(target_jsonl, baseline_name=None, baseline_jsonl=None):
    print_banner()

    # Load target
    target_events = parse_jsonl(target_jsonl)
    if not target_events:
        print(f"ERROR: No events in {target_jsonl}", file=sys.stderr)
        sys.exit(1)
    target_counts = events_to_counts(target_events)

    # Infer process name from events for baseline lookup
    proc_names = set(e.get('process','') for e in target_events)
    inferred_name = next(iter(proc_names), None)

    # Load baseline
    baseline_counts = None
    baseline_label  = None

    if baseline_jsonl:
        b_events = parse_jsonl(baseline_jsonl)
        if not b_events:
            print(f"ERROR: No events in baseline {baseline_jsonl}", file=sys.stderr)
            sys.exit(1)
        baseline_counts = events_to_counts(b_events)
        baseline_label  = Path(baseline_jsonl).name
    elif baseline_name:
        baseline_counts = load_baseline_counts(baseline_name)
        baseline_label  = f"stored baseline '{baseline_name}'"
        if baseline_counts is None:
            print(f"ERROR: No stored baseline named '{baseline_name}'", file=sys.stderr)
            print("Run with --list-baselines to see available baselines.")
            sys.exit(1)
    elif inferred_name:
        baseline_counts = load_baseline_counts(inferred_name)
        baseline_label  = f"stored baseline '{inferred_name}'"
        if baseline_counts is None:
            print(f"No stored baseline for '{inferred_name}'.")
            print(f"Run: python3 monitor.py --save-baseline <jsonl> --target {inferred_name}")
            sys.exit(1)
    else:
        print("ERROR: Cannot determine baseline. Use --baseline-name or --baseline-file")
        sys.exit(1)

    target_label  = Path(target_jsonl).name
    b_score, _, _ = compute_threat_score(baseline_counts)
    t_score, _, _ = compute_threat_score(target_counts)

    print_summary(baseline_counts, f"BASELINE: {baseline_label}")
    print_summary(target_counts,   f"TARGET:   {target_label}")

    anomalies = compare_runs(baseline_counts, target_counts)
    print_anomalies(anomalies, b_score, t_score, baseline_label, target_label)
    print()


def mode_interactive():
    print_banner()
    logs_dir = LOGS_DIR if LOGS_DIR.is_dir() else None

    print("\n[1/2] Select BASELINE log...")
    if TKINTER_AVAILABLE:
        baseline_path = select_file_gui("Select BASELINE log", logs_dir)
    else:
        baseline_path = select_file_cli("Select BASELINE log", logs_dir)
    if not baseline_path:
        print("No baseline selected."); return

    print("[2/2] Select TARGET log...")
    if TKINTER_AVAILABLE:
        target_path = select_file_gui("Select TARGET log", logs_dir)
    else:
        target_path = select_file_cli("Select TARGET log", logs_dir)
    if not target_path:
        print("No target selected."); return

    # Detect JSONL vs plaintext
    if str(baseline_path).endswith('.jsonl'):
        b_events = parse_jsonl(baseline_path)
        baseline_counts = events_to_counts(b_events)
    else:
        num_counts = parse_log(baseline_path)
        baseline_counts = Counter({SYSCALL_NAMES.get(k, f'unknown({k})'): v for k, v in num_counts.items()})

    if str(target_path).endswith('.jsonl'):
        t_events = parse_jsonl(target_path)
        target_counts = events_to_counts(t_events)
    else:
        num_counts = parse_log(target_path)
        target_counts = Counter({SYSCALL_NAMES.get(k, f'unknown({k})'): v for k, v in num_counts.items()})

    if not baseline_counts or not target_counts:
        print("ERROR: One or both files empty/unreadable."); return

    b_score, _, _ = compute_threat_score(baseline_counts)
    t_score, _, _ = compute_threat_score(target_counts)

    print_summary(baseline_counts, f"BASELINE: {baseline_path.name}")
    print_summary(target_counts,   f"TARGET:   {target_path.name}")

    anomalies = compare_runs(baseline_counts, target_counts)
    print_anomalies(anomalies, b_score, t_score, baseline_path.name, target_path.name)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Scrutiny Monitor - Behavioral Analysis Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 monitor.py                                       # interactive mode
  python3 monitor.py --summary logs/targetProc2/json/x.jsonl
  python3 monitor.py --save-baseline logs/.../x.jsonl --target targetProc0
  python3 monitor.py --compare logs/.../x.jsonl           # auto-detect baseline
  python3 monitor.py --compare logs/.../x.jsonl --baseline-name targetProc0
  python3 monitor.py --compare logs/.../x.jsonl --baseline-file logs/.../b.jsonl
  python3 monitor.py --list-baselines
        """
    )
    parser.add_argument('--summary',        metavar='JSONL',  help='Print summary for a single JSONL file')
    parser.add_argument('--save-baseline',  metavar='JSONL',  help='Store a JSONL as a named baseline')
    parser.add_argument('--target',         metavar='NAME',   help='Target name for --save-baseline')
    parser.add_argument('--compare',        metavar='JSONL',  help='Compare a JSONL against a baseline')
    parser.add_argument('--baseline-name',  metavar='NAME',   help='Stored baseline name for --compare')
    parser.add_argument('--baseline-file',  metavar='JSONL',  help='Explicit baseline JSONL for --compare')
    parser.add_argument('--list-baselines', action='store_true', help='List stored baselines')

    args = parser.parse_args()

    if args.list_baselines:
        list_baselines()
    elif args.summary:
        mode_summary(args.summary)
    elif args.save_baseline:
        mode_store_baseline(args.save_baseline, args.target)
    elif args.compare:
        mode_compare(args.compare, args.baseline_name, args.baseline_file)
    else:
        mode_interactive()


if __name__ == '__main__':
    main()
