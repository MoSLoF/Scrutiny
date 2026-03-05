#!/usr/bin/env python3
"""
monitor.py - Scrutiny behavioral analysis engine

Phase 2: Added syscall risk scoring with weighted severity tiers.
Anomaly detection now produces a threat score in addition to
presence/frequency analysis.

Risk Tiers:
  CRITICAL (10): execve, connect, sendto, ptrace, init_module,
                 finit_module, delete_module, kexec_load, bpf,
                 process_vm_writev, kexec_file_load, execveat,
                 sendmsg, sendmmsg
  HIGH     ( 7): socket, access, chmod, fchmod, chown, fchown,
                 kill, setuid, setgid, mount, chroot, pivot_root,
                 capset, prctl, seccomp, umount2
  MEDIUM   ( 3): open, openat, read, write, unlink, unlinkat,
                 rename, fork, clone, vfork, bind, listen,
                 accept, accept4
  LOW      ( 1): everything else

Part of the Scrutiny project - HoneyBadger Vanguard fork.
Inspired by the original work of CommonTongue-InfoSec.
https://github.com/CommonTongue-InfoSec/Scrutiny
"""

import os
import re
from collections import Counter

try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Syscall risk scoring table
# Keyed by syscall name -> (tier_label, score)
# ---------------------------------------------------------------------------
RISK_TABLE = {
    # CRITICAL - direct execution, kernel manipulation, network exfil
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

    # HIGH - privilege changes, suspicious file ops, process signaling
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

    # MEDIUM - file I/O, process creation, deletion
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
# Mirrors the corrected syscalls.c table
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


def get_syscall_name(syscall_num):
    return SYSCALL_NAMES.get(syscall_num, f'unknown({syscall_num})')


def get_risk(syscall_name):
    """Return (tier_label, score) for a syscall name."""
    return RISK_TABLE.get(syscall_name, ('LOW', 1))


def select_file(prompt, initial_dir=None):
    if TKINTER_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(
            title=prompt,
            initialdir=initial_dir if initial_dir and os.path.isdir(initial_dir)
                       else os.getcwd()
        )
        root.destroy()
        return file_path if file_path else None
    else:
        while True:
            file_path = input(f"{prompt} (enter path): ").strip()
            if os.path.isfile(file_path):
                return file_path
            print(f"Error: '{file_path}' not found. Try again.")


def parse_syscall_log(file_path):
    """Parse a baseliner log and return Counter of syscall numbers."""
    syscall_pattern = r"Syscall: (\d+) \("
    syscalls = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = re.search(syscall_pattern, line)
                if match:
                    syscalls.append(int(match.group(1)))
        return Counter(syscalls)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return Counter()


def compute_threat_score(syscall_counts):
    """
    Compute weighted threat score for a log.
    Returns: (total_score, tier_event_counts, tier_score_totals)
    """
    total_score = 0
    tier_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    tier_scores = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

    for syscall_num, count in syscall_counts.items():
        name = get_syscall_name(syscall_num)
        tier, score = get_risk(name)
        weighted = count * score
        total_score += weighted
        tier_counts[tier] += count
        tier_scores[tier] += weighted

    return total_score, tier_counts, tier_scores


def compare_syscalls(baseline_counts, target_counts):
    """
    Compare baseline vs target.
    Returns list of anomalies sorted by risk score descending.
    Each entry: (syscall_num, name, tier, score, description)
    """
    anomalies = []
    all_syscalls = set(baseline_counts.keys()) | set(target_counts.keys())
    total_baseline = sum(baseline_counts.values()) or 1
    total_target   = sum(target_counts.values()) or 1

    for syscall_num in sorted(all_syscalls):
        b_count = baseline_counts.get(syscall_num, 0)
        t_count = target_counts.get(syscall_num, 0)
        b_freq  = b_count / total_baseline
        t_freq  = t_count / total_target
        name    = get_syscall_name(syscall_num)
        tier, score = get_risk(name)

        if b_count == 0 and t_count > 0:
            anomalies.append((
                syscall_num, name, tier, score,
                f"NEW in target ({t_count}x, absent in baseline)"
            ))
        elif b_freq > 0 and t_freq > 2 * b_freq and t_count > 1:
            ratio = t_freq / b_freq
            anomalies.append((
                syscall_num, name, tier, score,
                f"FREQUENCY spike {ratio:.1f}x baseline "
                f"(baseline={b_count}, target={t_count})"
            ))

    anomalies.sort(key=lambda x: x[3], reverse=True)
    return anomalies


def print_summary(counts, label):
    """Print syscall frequency summary with risk annotation."""
    SEP = '=' * 62
    print(f"\n{SEP}")
    print(f"  {label}")
    print(SEP)

    total = sum(counts.values()) or 1
    total_score, tier_counts, tier_scores = compute_threat_score(counts)

    print(f"  Total syscall events : {total:,}")
    print(f"  Threat score         : {total_score:,}")
    print(f"  Tier breakdown       : "
          f"CRITICAL={tier_counts['CRITICAL']}  "
          f"HIGH={tier_counts['HIGH']}  "
          f"MEDIUM={tier_counts['MEDIUM']}  "
          f"LOW={tier_counts['LOW']}")
    print(f"\n  {'Syscall':<26} {'Count':>6}  {'Freq':>7}  {'Tier':<10} {'Pts':>5}")
    print(f"  {'-'*58}")

    for num, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        name = get_syscall_name(num)
        tier, score = get_risk(name)
        freq = count / total
        print(f"  {name:<26} {count:>6}  {freq:>7.4f}  {tier:<10} {score:>5}")


def print_analysis(anomalies, baseline_score, target_score):
    """Print final anomaly report with threat scores."""
    SEP = '=' * 62
    print(f"\n{SEP}")
    print(f"  ANOMALY ANALYSIS")
    print(SEP)
    print(f"  Baseline threat score : {baseline_score:,}")
    print(f"  Target threat score   : {target_score:,}")

    delta = target_score - baseline_score
    pct   = (delta / baseline_score * 100) if baseline_score > 0 else 0
    print(f"  Delta                 : {delta:+,} ({pct:+.1f}%)")

    if not anomalies:
        print("\n  [CLEAN] No significant anomalies detected.")
        return

    print(f"\n  {len(anomalies)} anomalies detected (sorted by risk):\n")
    print(f"  {'#':<4} {'Tier':<6} {'Score':>5}  {'Syscall':<24}  Description")
    print(f"  {'-'*68}")

    TIER_TAG = {
        'CRITICAL': '[!!!]',
        'HIGH':     '[ ! ]',
        'MEDIUM':   '[ ~ ]',
        'LOW':      '[   ]',
    }

    for i, (num, name, tier, score, desc) in enumerate(anomalies, 1):
        tag = TIER_TAG.get(tier, '     ')
        print(f"  {i:<4} {tag} {score:>5}  {name:<24}  {desc}")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir   = os.path.abspath(os.path.join(script_dir, '..', 'logs'))
    if not os.path.isdir(logs_dir):
        print(f"Warning: logs dir '{logs_dir}' not found; opening from cwd.")
        logs_dir = None

    print("=" * 62)
    print("  Scrutiny Monitor v2.0 - Risk-Scored Behavioral Analysis")
    print("=" * 62)

    print("\nSelect the BASELINE syscall log file...")
    baseline_file = select_file("Select baseline log", initial_dir=logs_dir)
    if not baseline_file:
        print("No baseline file selected. Exiting.")
        return

    print("Select the TARGET syscall log file...")
    target_file = select_file("Select target log", initial_dir=logs_dir)
    if not target_file:
        print("No target file selected. Exiting.")
        return

    baseline_counts = parse_syscall_log(baseline_file)
    target_counts   = parse_syscall_log(target_file)

    if not baseline_counts:
        print("Baseline log is empty or unreadable.")
        return
    if not target_counts:
        print("Target log is empty or unreadable.")
        return

    print_summary(baseline_counts, f"BASELINE: {os.path.basename(baseline_file)}")
    print_summary(target_counts,   f"TARGET:   {os.path.basename(target_file)}")

    baseline_score, _, _ = compute_threat_score(baseline_counts)
    target_score,   _, _ = compute_threat_score(target_counts)

    anomalies = compare_syscalls(baseline_counts, target_counts)
    print_analysis(anomalies, baseline_score, target_score)
    print()


if __name__ == '__main__':
    main()
