/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Server - Hash computation service header
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __STREAMHASH_SERVER_H
#define __STREAMHASH_SERVER_H

#include <time.h>
#include <pthread.h>

// libclamav
#include "clamav.h"

// common
#include "optparser.h"

// StreamHash command definitions
#define SHCMD_PING        "PING"
#define SHCMD_VERSION     "VERSION"
#define SHCMD_REBOOT      "REBOOT"
#define SHCMD_SHUTDOWN    "SHUTDOWN"
#define SHCMD_STATS       "STATS"
#define SHCMD_SCAN        "SCAN"
#define SHCMD_SCANSTREAM  "SCANSTREAM"
#define SHCMD_QUIT        "QUIT"

// Server configuration
#define STREAMHASH_DEFAULT_PORT 3399
#define STREAMHASH_MAX_QUEUE 10
#define STREAMHASH_TIMEOUT 120

// Task queue structure
struct streamhash_task {
    int id;
    char *command;
    char *target;
    time_t created;
    size_t files_scanned;
    size_t bytes_scanned;
    int status; // 0=pending, 1=running, 2=completed, 3=error
    struct streamhash_task *next;
};

struct streamhash_stats {
    unsigned int total_tasks;
    unsigned int active_tasks;
    unsigned int completed_tasks;
    unsigned int failed_tasks;
    size_t total_files;
    size_t total_bytes;
    time_t start_time;
    pthread_mutex_t stats_mutex;
};

struct streamhash_session {
    int socket;
    char client_ip[64];
    char client_id[64];
    time_t start_time;
    int current_task_id;
    pthread_t thread;
};

// Global server state
extern struct streamhash_stats g_stats;
extern struct streamhash_task *g_task_queue;
extern pthread_mutex_t g_queue_mutex;
extern int g_shutdown_requested;
extern int g_reboot_requested;

// Server functions
int streamhash_server_init(const struct optstruct *opts);
int streamhash_server_run(void);
void streamhash_server_cleanup(void);

// Task management functions
int streamhash_task_add(const char *command, const char *target, const char *client_ip, const char *client_id);
struct streamhash_task *streamhash_task_get_next(void);
void streamhash_task_complete(int task_id, int status);
void streamhash_task_free(struct streamhash_task *task);

// Session management
void *streamhash_session_thread(void *arg);
int streamhash_handle_command(struct streamhash_session *session, const char *command);

// Signal handlers
void streamhash_sighandler(int sig);

#endif /* __STREAMHASH_SERVER_H */