/*
 * baseliner.c - Scrutiny process syscall capture engine
 *
 * Phase 3: Added parallel JSON Lines logging alongside plaintext.
 * Each syscall event is written to both:
 *   logs/<proc>/<timestamp>.log      (plaintext, backward compat)
 *   logs/<proc>/json/<timestamp>.jsonl  (JSON Lines, Wazuh-ready)
 *
 * JSON schema per line:
 * {
 *   "timestamp": "2026-03-05T13:16:20Z",
 *   "pid": 919,
 *   "process": "targetProc2",
 *   "syscall_num": 44,
 *   "syscall_name": "sendto",
 *   "risk_tier": "CRITICAL",
 *   "risk_score": 10
 * }
 *
 * Part of the Scrutiny project - HoneyBadger Vanguard fork.
 */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "syscalls.h"
#include "utils.h"

pid_t target_pid = 0;
FILE *g_log      = NULL;
FILE *g_json_log = NULL;

void handle_sigint(int sig)
{
    if (target_pid > 0)
    {
        printf("\nBaseliner: Caught Ctrl+C, detaching from PID %d\n", target_pid);
        if (ptrace(PTRACE_CONT, target_pid, NULL, NULL) == -1)
            fprintf(stderr, "PTRACE_CONT failed in SIGINT: %s\n", strerror(errno));

        if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1)
            fprintf(stderr, "PTRACE_DETACH failed in SIGINT: %s\n", strerror(errno));
    }
    if (g_log)      fclose(g_log);
    if (g_json_log) fclose(g_json_log);
    exit(0);
}

void log_syscall(long syscall_num, pid_t pid, const char *proc_name,
                 FILE *log, FILE *json_log)
{
    const char *name  = get_syscall_name(syscall_num);
    const char *tier  = get_risk_tier(name);
    int         score = get_risk_score(name);

    /* --- plaintext log (existing format, unchanged) --- */
    time_t now = time(NULL);
    char *ts_str = ctime(&now);
    ts_str[strlen(ts_str) - 1] = '\0';
    fprintf(log, "[%s] Syscall: %ld (%s)\n", ts_str, syscall_num, name);
    fflush(log);

    /* --- JSON Lines log (Wazuh-ready) --- */
    /* ISO 8601 UTC timestamp */
    struct tm *utc = gmtime(&now);
    char iso[32];
    strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", utc);

    fprintf(json_log,
        "{\"timestamp\":\"%s\","
        "\"pid\":%d,"
        "\"process\":\"%s\","
        "\"syscall_num\":%ld,"
        "\"syscall_name\":\"%s\","
        "\"risk_tier\":\"%s\","
        "\"risk_score\":%d}\n",
        iso, (int)pid, proc_name, syscall_num, name, tier, score);
    fflush(json_log);
}

int main()
{
    pid_t pid;

    printf("Enter PID to trace: ");
    if (scanf("%d", &pid) != 1 || pid <= 0)
    {
        fprintf(stderr, "Invalid PID entered\n");
        return 1;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        fprintf(stderr, "PTRACE_ATTACH failed: %s\n", strerror(errno));
        return 1;
    }

    int status;
    if (waitpid(pid, &status, 0) == -1)
    {
        fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    printf("Baseliner: Successfully attached to PID %d\n", pid);

    char *proc_name = get_process_name(pid);
    if (!proc_name)
    {
        fprintf(stderr, "Failed to get process name\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* Create log directories */
    mkdir("logs", 0755);
    char proc_dir[512];
    snprintf(proc_dir, sizeof(proc_dir), "logs/%s", proc_name);
    mkdir(proc_dir, 0755);

    char json_dir[640];
    snprintf(json_dir, sizeof(json_dir), "%s/json", proc_dir);
    mkdir(json_dir, 0755);

    /* Build timestamp string for filenames */
    time_t now = time(NULL);
    struct tm *tm_local = localtime(&now);
    char ts_file[32];
    strftime(ts_file, sizeof(ts_file), "%Y-%m-%d_%H-%M", tm_local);

    /* Plaintext log */
    char log_path[1024];
    snprintf(log_path, sizeof(log_path), "%s/%s.log", proc_dir, ts_file);
    g_log = fopen(log_path, "w");
    if (!g_log)
    {
        fprintf(stderr, "Failed to open log file %s: %s\n",
                log_path, strerror(errno));
        free(proc_name);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("Baseliner: Logging to %s\n", log_path);

    /* JSON Lines log */
    char json_path[1024];
    snprintf(json_path, sizeof(json_path), "%s/%s.jsonl", json_dir, ts_file);
    g_json_log = fopen(json_path, "w");
    if (!g_json_log)
    {
        fprintf(stderr, "Failed to open JSON log %s: %s\n",
                json_path, strerror(errno));
        free(proc_name);
        fclose(g_log);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("Baseliner: JSON logging to %s\n", json_path);

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
    {
        fprintf(stderr, "PTRACE_SYSCALL failed: %s\n", strerror(errno));
        free(proc_name);
        fclose(g_log);
        fclose(g_json_log);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    target_pid = pid;
    signal(SIGINT, handle_sigint);

    printf("Baseliner: Tracing system calls (press Ctrl+C to stop)...\n");

    int in_syscall = 0;
    while (1)
    {
        if (waitpid(pid, &status, 0) == -1)
        {
            fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
        {
            printf("Baseliner: Target PID %d exited\n", pid);
            break;
        }

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
            {
                fprintf(stderr, "PTRACE_GETREGS failed: %s\n", strerror(errno));
                break;
            }
            if (!in_syscall)
            {
                long syscall_num = regs.orig_rax;
                log_syscall(syscall_num, pid, proc_name, g_log, g_json_log);
            }
            in_syscall = !in_syscall;
        }

        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
        {
            fprintf(stderr, "PTRACE_SYSCALL failed in loop: %s\n", strerror(errno));
            break;
        }
    }

    free(proc_name);
    fclose(g_log);
    fclose(g_json_log);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("Baseliner: Detached and finished\n");

    return 0;
}
