/*
 * syscalls.c - Linux x86_64 syscall lookup table
 *
 * Corrected against the authoritative kernel source:
 *   arch/x86/entry/syscalls/syscall_64.tbl
 *
 * Phase 2 fix: upstream table had 241 incorrect mappings
 * starting at syscall 94 due to offset shift errors.
 * All entries verified against Linux kernel 6.x.
 *
 * Part of the Scrutiny project - HoneyBadger Vanguard fork.
 */

#include "syscalls.h"
#include <stddef.h>
#include <string.h>

const struct syscall_map syscall_table[] = {
    {    0, "read"                   },  /* Read from file descriptor */
    {    1, "write"                  },  /* Write to file descriptor */
    {    2, "open"                   },  /* Open file */
    {    3, "close"                  },  /* Close file descriptor */
    {    4, "stat"                   },  /* Get file status */
    {    5, "fstat"                  },  /* Get file status by fd */
    {    6, "lstat"                  },  /* Get symbolic link status */
    {    7, "poll"                   },  /* Wait for events on file descriptors */
    {    8, "lseek"                  },  /* Reposition file offset */
    {    9, "mmap"                   },  /* Map files or devices into memory */
    {   10, "mprotect"               },  /* Set memory region protection */
    {   11, "munmap"                 },  /* Unmap memory region */
    {   12, "brk"                    },  /* Change data segment size */
    {   13, "rt_sigaction"           },  /* Examine and change signal action */
    {   14, "rt_sigprocmask"         },  /* Examine and change blocked signals */
    {   15, "rt_sigreturn"           },  /* Return from signal handler */
    {   16, "ioctl"                  },  /* Device control */
    {   17, "pread64"                },  /* Read from file at offset */
    {   18, "pwrite64"               },  /* Write to file at offset */
    {   19, "readv"                  },  /* Read into multiple buffers */
    {   20, "writev"                 },  /* Write from multiple buffers */
    {   21, "access"                 },  /* Check file accessibility */
    {   22, "pipe"                   },  /* Create pipe */
    {   23, "select"                 },  /* Synchronous I/O multiplexing */
    {   24, "sched_yield"            },  /* Yield CPU */
    {   25, "mremap"                 },  /* Remap virtual memory address */
    {   26, "msync"                  },  /* Synchronize memory with storage */
    {   27, "mincore"                },  /* Check memory residency */
    {   28, "madvise"                },  /* Give memory usage advice */
    {   29, "shmget"                 },  /* Get shared memory segment */
    {   30, "shmat"                  },  /* Attach shared memory segment */
    {   31, "shmctl"                 },  /* Shared memory control */
    {   32, "dup"                    },  /* Duplicate file descriptor */
    {   33, "dup2"                   },  /* Duplicate fd to specific number */
    {   34, "pause"                  },  /* Suspend process until signal */
    {   35, "nanosleep"              },  /* High-resolution sleep */
    {   36, "getitimer"              },  /* Get value of interval timer */
    {   37, "alarm"                  },  /* Set alarm signal timer */
    {   38, "setitimer"              },  /* Set value of interval timer */
    {   39, "getpid"                 },  /* Get process ID */
    {   40, "sendfile"               },  /* Transfer data between file descriptors */
    {   41, "socket"                 },  /* Create communication endpoint */
    {   42, "connect"                },  /* Initiate connection on socket */
    {   43, "accept"                 },  /* Accept connection on socket */
    {   44, "sendto"                 },  /* Send message on socket */
    {   45, "recvfrom"               },  /* Receive message from socket */
    {   46, "sendmsg"                },  /* Send message on socket */
    {   47, "recvmsg"                },  /* Receive message from socket */
    {   48, "shutdown"               },  /* Shut down socket connection */
    {   49, "bind"                   },  /* Bind name to socket */
    {   50, "listen"                 },  /* Listen for connections on socket */
    {   51, "getsockname"            },  /* Get socket name */
    {   52, "getpeername"            },  /* Get peer socket name */
    {   53, "socketpair"             },  /* Create pair of connected sockets */
    {   54, "setsockopt"             },  /* Set socket options */
    {   55, "getsockopt"             },  /* Get socket options */
    {   56, "clone"                  },  /* Create child process or thread */
    {   57, "fork"                   },  /* Create child process */
    {   58, "vfork"                  },  /* Create child process, suspend parent */
    {   59, "execve"                 },  /* Execute program */
    {   60, "exit"                   },  /* Terminate process */
    {   61, "wait4"                  },  /* Wait for process, BSD style */
    {   62, "kill"                   },  /* Send signal to process */
    {   63, "uname"                  },  /* Get system information */
    {   64, "semget"                 },  /* Get System V semaphore set */
    {   65, "semop"                  },  /* System V semaphore operations */
    {   66, "semctl"                 },  /* System V semaphore control */
    {   67, "shmdt"                  },  /* Detach shared memory segment */
    {   68, "msgget"                 },  /* Get System V message queue */
    {   69, "msgsnd"                 },  /* Send message to queue */
    {   70, "msgrcv"                 },  /* Receive message from queue */
    {   71, "msgctl"                 },  /* System V message queue control */
    {   72, "fcntl"                  },  /* File descriptor control */
    {   73, "flock"                  },  /* Apply or remove file lock */
    {   74, "fsync"                  },  /* Synchronize file data to storage */
    {   75, "fdatasync"              },  /* Synchronize file data only */
    {   76, "truncate"               },  /* Truncate file to specified length */
    {   77, "ftruncate"              },  /* Truncate file by descriptor */
    {   78, "getdents"               },  /* Get directory entries */
    {   79, "getcwd"                 },  /* Get current working directory */
    {   80, "chdir"                  },  /* Change working directory */
    {   81, "fchdir"                 },  /* Change working directory by fd */
    {   82, "rename"                 },  /* Rename file */
    {   83, "mkdir"                  },  /* Create directory */
    {   84, "rmdir"                  },  /* Remove directory */
    {   85, "creat"                  },  /* Create file */
    {   86, "link"                   },  /* Create hard link */
    {   87, "unlink"                 },  /* Delete file name */
    {   88, "symlink"                },  /* Create symbolic link */
    {   89, "readlink"               },  /* Read value of symbolic link */
    {   90, "chmod"                  },  /* Change file permissions */
    {   91, "fchmod"                 },  /* Change file permissions by fd */
    {   92, "chown"                  },  /* Change file owner and group */
    {   93, "fchown"                 },  /* Change file owner by fd */
    {   94, "lchown"                 },  /* Change symbolic link owner */
    {   95, "umask"                  },  /* Set file mode creation mask */
    {   96, "gettimeofday"           },  /* Get time and timezone */
    {   97, "getrlimit"              },  /* Get resource limits */
    {   98, "getrusage"              },  /* Get resource usage */
    {   99, "sysinfo"                },  /* Get system statistics */
    {  100, "times"                  },  /* Get process times */
    {  101, "ptrace"                 },  /* Process trace */
    {  102, "getuid"                 },  /* Get real user ID */
    {  103, "syslog"                 },  /* Read and clear kernel message ring buffer */
    {  104, "getgid"                 },  /* Get real group ID */
    {  105, "setuid"                 },  /* Set real user ID */
    {  106, "setgid"                 },  /* Set real group ID */
    {  107, "geteuid"                },  /* Get effective user ID */
    {  108, "getegid"                },  /* Get effective group ID */
    {  109, "setpgid"                },  /* Set process group ID */
    {  110, "getppid"                },  /* Get parent process ID */
    {  111, "getpgrp"                },  /* Get process group */
    {  112, "setsid"                 },  /* Create session and set process group ID */
    {  113, "setreuid"               },  /* Set real and effective user IDs */
    {  114, "setregid"               },  /* Set real and effective group IDs */
    {  115, "getgroups"              },  /* Get supplementary group IDs */
    {  116, "setgroups"              },  /* Set supplementary group IDs */
    {  117, "setresuid"              },  /* Set real, effective, and saved user IDs */
    {  118, "getresuid"              },  /* Get real, effective, and saved user IDs */
    {  119, "setresgid"              },  /* Set real, effective, and saved group IDs */
    {  120, "getresgid"              },  /* Get real, effective, and saved group IDs */
    {  121, "getpgid"                },  /* Get process group ID */
    {  122, "setfsuid"               },  /* Set user ID used for filesystem checks */
    {  123, "setfsgid"               },  /* Set group ID used for filesystem checks */
    {  124, "getsid"                 },  /* Get session ID */
    {  125, "capget"                 },  /* Get thread capabilities */
    {  126, "capset"                 },  /* Set thread capabilities */
    {  127, "rt_sigpending"          },  /* Examine pending signals */
    {  128, "rt_sigtimedwait"        },  /* Synchronously wait for queued signal */
    {  129, "rt_sigqueueinfo"        },  /* Queue signal and data */
    {  130, "rt_sigsuspend"          },  /* Wait for signal */
    {  131, "sigaltstack"            },  /* Set or get signal stack context */
    {  132, "utime"                  },  /* Change file last access and modification times */
    {  133, "mknod"                  },  /* Create special or ordinary file */
    {  134, "uselib"                 },  /* Load shared library */
    {  135, "personality"            },  /* Set the process execution domain */
    {  136, "ustat"                  },  /* Get filesystem statistics */
    {  137, "statfs"                 },  /* Get filesystem statistics */
    {  138, "fstatfs"                },  /* Get filesystem statistics by fd */
    {  139, "sysfs"                  },  /* Get filesystem type information */
    {  140, "getpriority"            },  /* Get program scheduling priority */
    {  141, "setpriority"            },  /* Set program scheduling priority */
    {  142, "sched_setparam"         },  /* Set scheduling parameters */
    {  143, "sched_getparam"         },  /* Get scheduling parameters */
    {  144, "sched_setscheduler"     },  /* Set scheduling policy and parameters */
    {  145, "sched_getscheduler"     },  /* Get scheduling policy */
    {  146, "sched_get_priority_max" },  /* Get static priority maximum */
    {  147, "sched_get_priority_min" },  /* Get static priority minimum */
    {  148, "sched_rr_get_interval"  },  /* Get round-robin time quantum */
    {  149, "mlock"                  },  /* Lock memory pages */
    {  150, "munlock"                },  /* Unlock memory pages */
    {  151, "mlockall"               },  /* Lock all memory pages */
    {  152, "munlockall"             },  /* Unlock all memory pages */
    {  153, "vhangup"                },  /* Virtually hangup current terminal */
    {  154, "modify_ldt"             },  /* Read or write local descriptor table */
    {  155, "pivot_root"             },  /* Change the root filesystem */
    {  156, "_sysctl"                },  /* Read/write system parameters */
    {  157, "prctl"                  },  /* Operations on a process */
    {  158, "arch_prctl"             },  /* Set architecture-specific thread state */
    {  159, "adjtimex"               },  /* Tune kernel clock */
    {  160, "setrlimit"              },  /* Set resource limits */
    {  161, "chroot"                 },  /* Change root directory */
    {  162, "sync"                   },  /* Flush filesystem buffers */
    {  163, "acct"                   },  /* Switch process accounting */
    {  164, "settimeofday"           },  /* Set time and timezone */
    {  165, "mount"                  },  /* Mount filesystem */
    {  166, "umount2"                },  /* Unmount filesystem */
    {  167, "swapon"                 },  /* Start swapping to file or device */
    {  168, "swapoff"                },  /* Stop swapping to file or device */
    {  169, "reboot"                 },  /* Reboot or halt the system */
    {  170, "sethostname"            },  /* Set hostname */
    {  171, "setdomainname"          },  /* Set NIS domain name */
    {  172, "iopl"                   },  /* Change I/O privilege level */
    {  173, "ioperm"                 },  /* Set I/O port permissions */
    {  174, "create_module"          },  /* Create a loadable module entry */
    {  175, "init_module"            },  /* Load a kernel module */
    {  176, "delete_module"          },  /* Unload a kernel module */
    {  177, "get_kernel_syms"        },  /* Retrieve exported kernel and module symbols */
    {  178, "query_module"           },  /* Query the kernel for various bits */
    {  179, "quotactl"               },  /* Manipulate disk quotas */
    {  180, "nfsservctl"             },  /* Syscall interface to kernel nfs daemon */
    {  181, "getpmsg"                },  /* Get message on stream */
    {  182, "putpmsg"                },  /* Put message on stream */
    {  183, "afs_syscall"            },  /* AFS syscall */
    {  184, "tuxcall"                },  /* TUX syscall */
    {  185, "security"               },  /* Security syscall */
    {  186, "gettid"                 },  /* Get thread identification */
    {  187, "readahead"              },  /* Initiate file readahead into page cache */
    {  188, "setxattr"               },  /* Set extended attribute value */
    {  189, "lsetxattr"              },  /* Set extended attribute value of symlink */
    {  190, "fsetxattr"              },  /* Set extended attribute value by fd */
    {  191, "getxattr"               },  /* Retrieve extended attribute value */
    {  192, "lgetxattr"              },  /* Retrieve extended attribute value of symlink */
    {  193, "fgetxattr"              },  /* Retrieve extended attribute value by fd */
    {  194, "listxattr"              },  /* List extended attribute names */
    {  195, "llistxattr"             },  /* List extended attribute names of symlink */
    {  196, "flistxattr"             },  /* List extended attribute names by fd */
    {  197, "removexattr"            },  /* Remove extended attribute */
    {  198, "lremovexattr"           },  /* Remove extended attribute of symlink */
    {  199, "fremovexattr"           },  /* Remove extended attribute by fd */
    {  200, "tkill"                  },  /* Send a signal to a thread */
    {  201, "time"                   },  /* Get time in seconds */
    {  202, "futex"                  },  /* Fast userspace locking */
    {  203, "sched_setaffinity"      },  /* Set thread CPU affinity mask */
    {  204, "sched_getaffinity"      },  /* Get thread CPU affinity mask */
    {  205, "set_thread_area"        },  /* Set thread-local storage area */
    {  206, "io_setup"               },  /* Create asynchronous I/O context */
    {  207, "io_destroy"             },  /* Destroy asynchronous I/O context */
    {  208, "io_getevents"           },  /* Read asynchronous I/O events */
    {  209, "io_submit"              },  /* Submit asynchronous I/O blocks */
    {  210, "io_cancel"              },  /* Cancel asynchronous I/O operation */
    {  211, "get_thread_area"        },  /* Get thread-local storage area */
    {  212, "lookup_dcookie"         },  /* Return a directory entry path */
    {  213, "epoll_create"           },  /* Open an epoll file descriptor */
    {  214, "epoll_ctl_old"          },  /* Control interface for epoll (deprecated) */
    {  215, "epoll_wait_old"         },  /* Wait for epoll event (deprecated) */
    {  216, "remap_file_pages"       },  /* Create nonlinear file mapping */
    {  217, "getdents64"             },  /* Get directory entries (64-bit) */
    {  218, "set_tid_address"        },  /* Set pointer to thread ID */
    {  219, "restart_syscall"        },  /* Restart a system call after interruption */
    {  220, "semtimedop"             },  /* System V semaphore operations with timeout */
    {  221, "fadvise64"              },  /* Predeclare file access pattern */
    {  222, "timer_create"           },  /* Create a POSIX per-process timer */
    {  223, "timer_settime"          },  /* Arm or disarm POSIX timer */
    {  224, "timer_gettime"          },  /* Fetch state of POSIX timer */
    {  225, "timer_getoverrun"       },  /* Get overrun count for a POSIX timer */
    {  226, "timer_delete"           },  /* Delete a POSIX timer */
    {  227, "clock_settime"          },  /* Set time of specified clock */
    {  228, "clock_gettime"          },  /* Retrieve time of specified clock */
    {  229, "clock_getres"           },  /* Find resolution of specified clock */
    {  230, "clock_nanosleep"        },  /* High resolution sleep with specifiable clock */
    {  231, "exit_group"             },  /* Exit all threads in a process */
    {  232, "epoll_wait"             },  /* Wait for epoll event */
    {  233, "epoll_ctl"              },  /* Control interface for epoll */
    {  234, "tgkill"                 },  /* Send a signal to a thread in a thread group */
    {  235, "utimes"                 },  /* Change file timestamps */
    {  236, "vserver"                },  /* Unimplemented */
    {  237, "mbind"                  },  /* Set memory policy for memory range */
    {  238, "set_mempolicy"          },  /* Set default NUMA memory policy */
    {  239, "get_mempolicy"          },  /* Retrieve NUMA memory policy */
    {  240, "mq_open"                },  /* Open a message queue */
    {  241, "mq_unlink"              },  /* Remove a message queue */
    {  242, "mq_timedsend"           },  /* Send a message to a queue */
    {  243, "mq_timedreceive"        },  /* Receive a message from a queue */
    {  244, "mq_notify"              },  /* Register for notification when a queue is non-empty */
    {  245, "mq_getsetattr"          },  /* Get or set message queue attributes */
    {  246, "kexec_load"             },  /* Load a new kernel for later execution */
    {  247, "waitid"                 },  /* Wait for process to change state */
    {  248, "add_key"                },  /* Add a key to the kernel keyring */
    {  249, "request_key"            },  /* Request a key from the kernel keyring */
    {  250, "keyctl"                 },  /* Manipulate the kernel key management facility */
    {  251, "ioprio_set"             },  /* Set I/O scheduling class and priority */
    {  252, "ioprio_get"             },  /* Get I/O scheduling class and priority */
    {  253, "inotify_init"           },  /* Initialize inotify instance */
    {  254, "inotify_add_watch"      },  /* Add watch to inotify instance */
    {  255, "inotify_rm_watch"       },  /* Remove watch from inotify instance */
    {  256, "migrate_pages"          },  /* Move all pages in a process to another set of nodes */
    {  257, "openat"                 },  /* Open file relative to directory fd */
    {  258, "mkdirat"                },  /* Create directory relative to directory fd */
    {  259, "mknodat"                },  /* Create special file relative to directory fd */
    {  260, "fchownat"               },  /* Change ownership relative to directory fd */
    {  261, "futimesat"              },  /* Change timestamps relative to directory fd */
    {  262, "newfstatat"             },  /* Get file status relative to directory fd */
    {  263, "unlinkat"               },  /* Remove file relative to directory fd */
    {  264, "renameat"               },  /* Rename file relative to directory fd */
    {  265, "linkat"                 },  /* Create hard link relative to directory fd */
    {  266, "symlinkat"              },  /* Create symbolic link relative to directory fd */
    {  267, "readlinkat"             },  /* Read symbolic link relative to directory fd */
    {  268, "fchmodat"               },  /* Change permissions relative to directory fd */
    {  269, "faccessat"              },  /* Check accessibility relative to directory fd */
    {  270, "pselect6"               },  /* Synchronous I/O multiplexing with signal mask */
    {  271, "ppoll"                  },  /* Wait for events with signal mask */
    {  272, "unshare"                },  /* Disassociate parts of process execution context */
    {  273, "set_robust_list"        },  /* Set list of robust futexes */
    {  274, "get_robust_list"        },  /* Get list of robust futexes */
    {  275, "splice"                 },  /* Splice data to or from a pipe */
    {  276, "tee"                    },  /* Duplicating pipe content */
    {  277, "sync_file_range"        },  /* Sync a file segment with disk */
    {  278, "vmsplice"               },  /* Splice user pages into a pipe */
    {  279, "move_pages"             },  /* Move individual pages of a process */
    {  280, "utimensat"              },  /* Change file timestamps with nanosecond precision */
    {  281, "epoll_pwait"            },  /* Wait for epoll event with signal mask */
    {  282, "signalfd"               },  /* Create file descriptor for accepting signals */
    {  283, "timerfd_create"         },  /* Create timer that notifies via file descriptor */
    {  284, "eventfd"                },  /* Create file descriptor for event notification */
    {  285, "fallocate"              },  /* Manipulate file space */
    {  286, "timerfd_settime"        },  /* Arm or disarm timer via file descriptor */
    {  287, "timerfd_gettime"        },  /* Get current setting of timer via file descriptor */
    {  288, "accept4"                },  /* Accept connection with flags */
    {  289, "signalfd4"              },  /* Create signal fd with flags */
    {  290, "eventfd2"               },  /* Create event fd with flags */
    {  291, "epoll_create1"          },  /* Open epoll file descriptor with flags */
    {  292, "dup3"                   },  /* Duplicate fd to specific number with flags */
    {  293, "pipe2"                  },  /* Create pipe with flags */
    {  294, "inotify_init1"          },  /* Initialize inotify instance with flags */
    {  295, "preadv"                 },  /* Read into multiple buffers at offset */
    {  296, "pwritev"                },  /* Write from multiple buffers at offset */
    {  297, "rt_tgsigqueueinfo"      },  /* Queue signal with data to thread group */
    {  298, "perf_event_open"        },  /* Set up performance monitoring */
    {  299, "recvmmsg"               },  /* Receive multiple messages on a socket */
    {  300, "fanotify_init"          },  /* Initialize fanotify group */
    {  301, "fanotify_mark"          },  /* Add, remove, or modify fanotify mark */
    {  302, "prlimit64"              },  /* Get or set resource limits */
    {  303, "name_to_handle_at"      },  /* Obtain handle for a pathname */
    {  304, "open_by_handle_at"      },  /* Open file via a handle */
    {  305, "clock_adjtime"          },  /* Tune a specified clock */
    {  306, "syncfs"                 },  /* Commit filesystem containing fd to disk */
    {  307, "sendmmsg"               },  /* Send multiple messages on a socket */
    {  308, "setns"                  },  /* Reassociate thread with a namespace */
    {  309, "getcpu"                 },  /* Determine CPU and NUMA node */
    {  310, "process_vm_readv"       },  /* Transfer data from another process */
    {  311, "process_vm_writev"      },  /* Transfer data to another process */
    {  312, "kcmp"                   },  /* Compare two processes to determine if they share a resource */
    {  313, "finit_module"           },  /* Load a kernel module from file descriptor */
    {  314, "sched_setattr"          },  /* Set scheduling policy and attributes */
    {  315, "sched_getattr"          },  /* Get scheduling policy and attributes */
    {  316, "renameat2"              },  /* Rename file with flags */
    {  317, "seccomp"                },  /* Operate on secure computing state */
    {  318, "getrandom"              },  /* Obtain a series of random bytes */
    {  319, "memfd_create"           },  /* Create an anonymous file */
    {  320, "kexec_file_load"        },  /* Load new kernel for later execution */
    {  321, "bpf"                    },  /* Perform a command on an extended BPF map or program */
    {  322, "execveat"               },  /* Execute program relative to a directory fd */
    {  323, "userfaultfd"            },  /* Create file descriptor for handling page faults */
    {  324, "membarrier"             },  /* Issue memory barriers on a set of threads */
    {  325, "mlock2"                 },  /* Lock memory with flags */
    {  326, "copy_file_range"        },  /* Copy a range of data from one file to another */
    {  327, "preadv2"                },  /* Read into multiple buffers at offset with flags */
    {  328, "pwritev2"               },  /* Write from multiple buffers at offset with flags */
    {  329, "pkey_mprotect"          },  /* Set protection on a region of memory */
    {  330, "pkey_alloc"             },  /* Allocate a protection key */
    {  331, "pkey_free"              },  /* Free a protection key */
    {  332, "statx"                  },  /* Get file status (extended) */
    {  333, "io_pgetevents"          },  /* Read asynchronous I/O events from the completion queue */
    {  334, "rseq"                   },  /* Register restartable sequence for current thread */
    {  424, "pidfd_send_signal"      },  /* Send a signal to a process specified by a file descriptor */
    {  434, "pidfd_open"             },  /* Obtain a file descriptor that refers to a process */
    {  438, "pidfd_getfd"            },  /* Obtain a duplicate of another process file descriptor */
    {   -1, NULL                     }   /* sentinel */
};

const char *get_syscall_name(long syscall_num)
{
    for (int i = 0; syscall_table[i].num != -1; i++)
    {
        if (syscall_table[i].num == syscall_num)
            return syscall_table[i].name;
    }
    return "unknown";
}

/* ---------------------------------------------------------------------------
 * Risk scoring - mirrors the Python RISK_TABLE in monitor.py.
 * Must be kept in sync with monitor.py RISK_TABLE when tiers are updated.
 * --------------------------------------------------------------------------- */

static const char *CRITICAL_SYSCALLS[] = {
    "execve", "execveat", "connect", "sendto", "sendmsg", "sendmmsg",
    "ptrace", "init_module", "finit_module", "delete_module",
    "kexec_load", "kexec_file_load", "bpf", "process_vm_writev",
    NULL
};

static const char *HIGH_SYSCALLS[] = {
    "socket", "access", "faccessat", "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "lchown", "fchownat",
    "kill", "tkill", "tgkill",
    "setuid", "setgid", "setreuid", "setregid",
    "setresuid", "setresgid", "setfsuid", "setfsgid",
    "capset", "mount", "umount2", "chroot", "pivot_root",
    "prctl", "seccomp",
    NULL
};

static const char *MEDIUM_SYSCALLS[] = {
    "open", "openat", "openat2", "read", "write",
    "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "fork", "vfork", "clone",
    "bind", "listen", "accept", "accept4",
    NULL
};

static int name_in_list(const char *name, const char **list)
{
    for (int i = 0; list[i] != NULL; i++)
        if (strcmp(name, list[i]) == 0) return 1;
    return 0;
}

const char *get_risk_tier(const char *syscall_name)
{
    if (!syscall_name) return "LOW";
    if (name_in_list(syscall_name, CRITICAL_SYSCALLS)) return "CRITICAL";
    if (name_in_list(syscall_name, HIGH_SYSCALLS))     return "HIGH";
    if (name_in_list(syscall_name, MEDIUM_SYSCALLS))   return "MEDIUM";
    return "LOW";
}

int get_risk_score(const char *syscall_name)
{
    if (!syscall_name) return 1;
    if (name_in_list(syscall_name, CRITICAL_SYSCALLS)) return 10;
    if (name_in_list(syscall_name, HIGH_SYSCALLS))     return 7;
    if (name_in_list(syscall_name, MEDIUM_SYSCALLS))   return 3;
    return 1;
}
