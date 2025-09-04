/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Server Implementation
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

// libclamav
#include "clamav.h"
#include "others.h"

// common
#include "output.h"
#include "misc.h"

#include "streamhash_server.h"
#include "streamhash_hash.h"

// Global variables
struct streamhash_stats g_stats;
struct streamhash_task *g_task_queue = NULL;
pthread_mutex_t g_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_shutdown_requested = 0;
int g_reboot_requested = 0;
int g_server_socket = -1;
static int g_task_counter = 1;

void streamhash_sighandler(int sig)
{
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            mprintf(LOGG_INFO, "Received shutdown signal %d\n", sig);
            g_shutdown_requested = 1;
            break;
        case SIGUSR1:
            mprintf(LOGG_INFO, "Received reboot signal\n");
            g_reboot_requested = 1;
            break;
        default:
            mprintf(LOGG_INFO, "Received signal %d\n", sig);
            break;
    }
}

int streamhash_server_init(const struct optstruct *opts)
{
    // Initialize statistics
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.start_time = time(NULL);
    if (pthread_mutex_init(&g_stats.stats_mutex, NULL) != 0) {
        mprintf(LOGG_ERROR, "Failed to initialize stats mutex\n");
        return -1;
    }
    
    // Set up signal handlers
    signal(SIGTERM, streamhash_sighandler);
    signal(SIGINT, streamhash_sighandler);
    signal(SIGUSR1, streamhash_sighandler);
    signal(SIGPIPE, SIG_IGN);
    
    mprintf(LOGG_INFO, "StreamHash server initialized\n");
    return 0;
}

int streamhash_server_run(void)
{
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    int client_socket;
    pthread_t thread;
    struct streamhash_session *session;
    
    // Create socket
    g_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_socket < 0) {
        mprintf(LOGG_ERROR, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        mprintf(LOGG_WARNING, "Failed to set SO_REUSEADDR: %s\n", strerror(errno));
    }
    
    // Bind socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(STREAMHASH_DEFAULT_PORT);
    
    if (bind(g_server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        mprintf(LOGG_ERROR, "Failed to bind socket: %s\n", strerror(errno));
        close(g_server_socket);
        return -1;
    }
    
    // Listen for connections
    if (listen(g_server_socket, STREAMHASH_MAX_QUEUE) < 0) {
        mprintf(LOGG_ERROR, "Failed to listen: %s\n", strerror(errno));
        close(g_server_socket);
        return -1;
    }
    
    mprintf(LOGG_INFO, "StreamHash server listening on port %d\n", STREAMHASH_DEFAULT_PORT);
    
    // Main server loop
    while (!g_shutdown_requested && !g_reboot_requested) {
        client_len = sizeof(client_addr);
        client_socket = accept(g_server_socket, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_socket < 0) {
            if (errno == EINTR) continue; // Interrupted by signal
            mprintf(LOGG_ERROR, "Failed to accept connection: %s\n", strerror(errno));
            continue;
        }
        
        // Create session structure
        session = malloc(sizeof(struct streamhash_session));
        if (!session) {
            mprintf(LOGG_ERROR, "Failed to allocate session memory\n");
            close(client_socket);
            continue;
        }
        
        session->socket = client_socket;
        strcpy(session->client_ip, inet_ntoa(client_addr.sin_addr));
        snprintf(session->client_id, sizeof(session->client_id), "user_%s", session->client_ip);
        session->start_time = time(NULL);
        session->current_task_id = 0;
        
        mprintf(LOGG_INFO, "New connection from %s\n", session->client_ip);
        
        // Create thread to handle the session
        if (pthread_create(&session->thread, NULL, streamhash_session_thread, session) != 0) {
            mprintf(LOGG_ERROR, "Failed to create session thread: %s\n", strerror(errno));
            close(client_socket);
            free(session);
            continue;
        }
        
        pthread_detach(session->thread);
    }
    
    close(g_server_socket);
    
    if (g_reboot_requested) {
        mprintf(LOGG_INFO, "Reboot requested - restarting\n");
        // In a real implementation, you'd exec the same program
        return 2; // Special return code for reboot
    }
    
    return 0;
}

void streamhash_server_cleanup(void)
{
    // Cleanup task queue
    pthread_mutex_lock(&g_queue_mutex);
    struct streamhash_task *task = g_task_queue;
    while (task) {
        struct streamhash_task *next = task->next;
        streamhash_task_free(task);
        task = next;
    }
    g_task_queue = NULL;
    pthread_mutex_unlock(&g_queue_mutex);
    
    pthread_mutex_destroy(&g_queue_mutex);
    pthread_mutex_destroy(&g_stats.stats_mutex);
    
    if (g_server_socket >= 0) {
        close(g_server_socket);
    }
    
    mprintf(LOGG_INFO, "StreamHash server cleanup completed\n");
}

int streamhash_task_add(const char *command, const char *target, const char *client_ip, const char *client_id)
{
    struct streamhash_task *task = malloc(sizeof(struct streamhash_task));
    if (!task) return -1;
    
    pthread_mutex_lock(&g_queue_mutex);
    
    task->id = g_task_counter++;
    task->command = strdup(command);
    task->target = strdup(target);
    task->created = time(NULL);
    task->files_scanned = 0;
    task->bytes_scanned = 0;
    task->status = 0; // pending
    task->next = NULL;
    
    // Add to end of queue
    if (!g_task_queue) {
        g_task_queue = task;
    } else {
        struct streamhash_task *curr = g_task_queue;
        while (curr->next) {
            curr = curr->next;
        }
        curr->next = task;
    }
    
    pthread_mutex_lock(&g_stats.stats_mutex);
    g_stats.total_tasks++;
    g_stats.active_tasks++;
    pthread_mutex_unlock(&g_stats.stats_mutex);
    
    int task_id = task->id;
    pthread_mutex_unlock(&g_queue_mutex);
    
    mprintf(LOGG_INFO, "Task %d added: %s %s\n", task_id, command, target);
    return task_id;
}

struct streamhash_task *streamhash_task_get_next(void)
{
    pthread_mutex_lock(&g_queue_mutex);
    
    struct streamhash_task *task = g_task_queue;
    if (task && task->status == 0) { // pending
        task->status = 1; // running
        pthread_mutex_unlock(&g_queue_mutex);
        return task;
    }
    
    pthread_mutex_unlock(&g_queue_mutex);
    return NULL;
}

void streamhash_task_complete(int task_id, int status)
{
    pthread_mutex_lock(&g_queue_mutex);
    
    struct streamhash_task *task = g_task_queue;
    while (task) {
        if (task->id == task_id) {
            task->status = status;
            break;
        }
        task = task->next;
    }
    
    pthread_mutex_lock(&g_stats.stats_mutex);
    g_stats.active_tasks--;
    if (status == 2) { // completed
        g_stats.completed_tasks++;
    } else {
        g_stats.failed_tasks++;
    }
    pthread_mutex_unlock(&g_stats.stats_mutex);
    
    pthread_mutex_unlock(&g_queue_mutex);
}

void streamhash_task_free(struct streamhash_task *task)
{
    if (!task) return;
    free(task->command);
    free(task->target);
    free(task);
}

void *streamhash_session_thread(void *arg)
{
    struct streamhash_session *session = (struct streamhash_session *)arg;
    char buffer[1024];
    char response[4096];
    ssize_t bytes_received;
    
    mprintf(LOGG_INFO, "Session thread started for %s\n", session->client_ip);
    
    // Send welcome message
    snprintf(response, sizeof(response), "StreamHash %s ready\n", get_version());
    send(session->socket, response, strlen(response), 0);
    
    // Main command processing loop
    while (!g_shutdown_requested) {
        bytes_received = recv(session->socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                mprintf(LOGG_INFO, "Client %s disconnected\n", session->client_ip);
            } else {
                mprintf(LOGG_INFO, "Recv error from %s: %s\n", session->client_ip, strerror(errno));
            }
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        // Remove trailing newline
        char *newline = strchr(buffer, '\n');
        if (newline) *newline = '\0';
        
        mprintf(LOGG_DEBUG, "Command from %s: %s\n", session->client_ip, buffer);
        
        // Process command
        int result = streamhash_handle_command(session, buffer);
        if (result == -1) {
            break; // Client requested quit
        }
    }
    
    close(session->socket);
    free(session);
    mprintf(LOGG_INFO, "Session thread ended for client\n");
    return NULL;
}

int streamhash_handle_command(struct streamhash_session *session, const char *command)
{
    char response[8192];
    
    if (strncmp(command, SHCMD_PING, strlen(SHCMD_PING)) == 0) {
        snprintf(response, sizeof(response), "PONG\n");
        send(session->socket, response, strlen(response), 0);
        
    } else if (strncmp(command, SHCMD_VERSION, strlen(SHCMD_VERSION)) == 0) {
        snprintf(response, sizeof(response), "StreamHash %s\n", get_version());
        send(session->socket, response, strlen(response), 0);
        
    } else if (strncmp(command, SHCMD_STATS, strlen(SHCMD_STATS)) == 0) {
        pthread_mutex_lock(&g_stats.stats_mutex);
        time_t uptime = time(NULL) - g_stats.start_time;
        snprintf(response, sizeof(response), 
                "STATS\n"
                "Uptime: %ld seconds\n"
                "Total tasks: %u\n"
                "Active tasks: %u\n"
                "Completed tasks: %u\n"
                "Failed tasks: %u\n"
                "Total files: %zu\n"
                "Total bytes: %zu\n",
                uptime, g_stats.total_tasks, g_stats.active_tasks,
                g_stats.completed_tasks, g_stats.failed_tasks,
                g_stats.total_files, g_stats.total_bytes);
        pthread_mutex_unlock(&g_stats.stats_mutex);
        send(session->socket, response, strlen(response), 0);
        
    } else if (strncmp(command, SHCMD_SCAN, strlen(SHCMD_SCAN)) == 0) {
        const char *filepath = command + strlen(SHCMD_SCAN);
        while (*filepath == ' ') filepath++; // Skip spaces
        
        if (strlen(filepath) == 0) {
            snprintf(response, sizeof(response), "ERROR: No file path specified\n");
            send(session->socket, response, strlen(response), 0);
            return 0;
        }
        
        // Add task to queue
        int task_id = streamhash_task_add(SHCMD_SCAN, filepath, session->client_ip, session->client_id);
        if (task_id < 0) {
            snprintf(response, sizeof(response), "ERROR: Failed to queue scan task\n");
            send(session->socket, response, strlen(response), 0);
            return 0;
        }
        
        session->current_task_id = task_id;
        
        // Process the scan immediately (simplified - no actual queue processing)
        struct streamhash_result result;
        if (streamhash_compute_all(filepath, session->client_ip, session->client_id, filepath, &result) == 0) {
            char *json_str = streamhash_result_to_json_string(&result);
            if (json_str) {
                snprintf(response, sizeof(response), "%s\n", json_str);
                free(json_str);
            } else {
                snprintf(response, sizeof(response), "ERROR: Failed to generate JSON output\n");
            }
            streamhash_task_complete(task_id, 2); // completed
            
            // Update stats
            pthread_mutex_lock(&g_stats.stats_mutex);
            g_stats.total_files++;
            g_stats.total_bytes += result.file_size;
            pthread_mutex_unlock(&g_stats.stats_mutex);
        } else {
            snprintf(response, sizeof(response), "ERROR: Failed to compute hashes for %s\n", filepath);
            streamhash_task_complete(task_id, 3); // error
        }
        
        send(session->socket, response, strlen(response), 0);
        
    } else if (strncmp(command, SHCMD_SHUTDOWN, strlen(SHCMD_SHUTDOWN)) == 0) {
        snprintf(response, sizeof(response), "Shutting down...\n");
        send(session->socket, response, strlen(response), 0);
        g_shutdown_requested = 1;
        
    } else if (strncmp(command, SHCMD_REBOOT, strlen(SHCMD_REBOOT)) == 0) {
        snprintf(response, sizeof(response), "Rebooting...\n");
        send(session->socket, response, strlen(response), 0);
        g_reboot_requested = 1;
        
    } else if (strncmp(command, SHCMD_QUIT, strlen(SHCMD_QUIT)) == 0) {
        snprintf(response, sizeof(response), "Goodbye\n");
        send(session->socket, response, strlen(response), 0);
        return -1; // Signal to close connection
        
    } else {
        snprintf(response, sizeof(response), "ERROR: Unknown command: %s\n", command);
        send(session->socket, response, strlen(response), 0);
    }
    
    return 0;
}