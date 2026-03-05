#ifndef SYSCALLS_H
#define SYSCALLS_H


struct syscall_map
{
    long        num;    /* Syscall number              */
    const char *name;   /* Syscall name                */
};


extern const struct syscall_map syscall_table[];


/* Lookup syscall name by number. Returns "unknown" if not found. */
const char *get_syscall_name(long syscall_num);

/*
 * Risk scoring - mirrors the Python RISK_TABLE in monitor.py.
 * Returns tier label: "CRITICAL", "HIGH", "MEDIUM", or "LOW".
 * Returns numeric score: 10, 7, 3, or 1.
 */
const char *get_risk_tier(const char *syscall_name);
int         get_risk_score(const char *syscall_name);


#endif
