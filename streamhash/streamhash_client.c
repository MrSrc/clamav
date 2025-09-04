/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Client Library - Implementation
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
#include <netdb.h>
#include <errno.h>

// common
#include "output.h"
#include "misc.h"

#include "streamhash_client.h"

#define STREAMHASH_DEFAULT_HOST "127.0.0.1"
#define STREAMHASH_DEFAULT_PORT 3399

struct streamhash_connection *streamhash_connect(const struct optstruct *opts)
{
    struct streamhash_connection *conn;
    struct sockaddr_in server_addr;
    struct hostent *host_entry;
    const char *hostname = STREAMHASH_DEFAULT_HOST;
    int port = STREAMHASH_DEFAULT_PORT;
    
    conn = malloc(sizeof(struct streamhash_connection));
    if (!conn) {
        mprintf(LOGG_ERROR, "Failed to allocate connection structure\n");
        return NULL;
    }
    
    // TODO: Parse hostname and port from opts
    strncpy(conn->server_host, hostname, sizeof(conn->server_host) - 1);
    conn->server_host[sizeof(conn->server_host) - 1] = '\0';
    conn->server_port = port;
    
    // Create socket
    conn->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->socket < 0) {
        mprintf(LOGG_ERROR, "Failed to create socket: %s\n", strerror(errno));
        free(conn);
        return NULL;
    }
    
    // Resolve hostname
    host_entry = gethostbyname(hostname);
    if (!host_entry) {
        mprintf(LOGG_ERROR, "Failed to resolve hostname %s\n", hostname);
        close(conn->socket);
        free(conn);
        return NULL;
    }
    
    // Connect to server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, host_entry->h_addr, host_entry->h_length);
    
    if (connect(conn->socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        mprintf(LOGG_ERROR, "Failed to connect to %s:%d: %s\n", hostname, port, strerror(errno));
        close(conn->socket);
        free(conn);
        return NULL;
    }
    
    // Read welcome message
    char *welcome = streamhash_recv_response(conn);
    if (welcome) {
        mprintf(LOGG_DEBUG, "Server: %s", welcome);
        free(welcome);
    }
    
    mprintf(LOGG_DEBUG, "Connected to StreamHash daemon at %s:%d\n", hostname, port);
    return conn;
}

void streamhash_disconnect(struct streamhash_connection *conn)
{
    if (!conn) return;
    
    // Send quit command
    streamhash_send_command(conn, "QUIT");
    
    close(conn->socket);
    free(conn);
}

int streamhash_send_command(struct streamhash_connection *conn, const char *command)
{
    if (!conn || !command) return -1;
    
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), "%s\n", command);
    
    ssize_t sent = send(conn->socket, buffer, strlen(buffer), 0);
    if (sent < 0) {
        mprintf(LOGG_ERROR, "Failed to send command: %s\n", strerror(errno));
        return -1;
    }
    
    mprintf(LOGG_DEBUG, "Sent command: %s\n", command);
    return 0;
}

char *streamhash_recv_response(struct streamhash_connection *conn)
{
    if (!conn) return NULL;
    
    ssize_t received = recv(conn->socket, conn->buffer, sizeof(conn->buffer) - 1, 0);
    if (received <= 0) {
        if (received == 0) {
            mprintf(LOGG_ERROR, "Server disconnected\n");
        } else {
            mprintf(LOGG_ERROR, "Failed to receive response: %s\n", strerror(errno));
        }
        return NULL;
    }
    
    conn->buffer[received] = '\0';
    mprintf(LOGG_DEBUG, "Received: %s", conn->buffer);
    
    return strdup(conn->buffer);
}

int streamhash_ping(struct streamhash_connection *conn)
{
    if (streamhash_send_command(conn, "PING") != 0) {
        return -1;
    }
    
    char *response = streamhash_recv_response(conn);
    if (!response) {
        return -1;
    }
    
    int result = (strncmp(response, "PONG", 4) == 0) ? 0 : -1;
    free(response);
    return result;
}

char *streamhash_get_version(struct streamhash_connection *conn)
{
    if (streamhash_send_command(conn, "VERSION") != 0) {
        return NULL;
    }
    
    return streamhash_recv_response(conn);
}

int streamhash_reload(struct streamhash_connection *conn)
{
    if (streamhash_send_command(conn, "REBOOT") != 0) {
        return -1;
    }
    
    char *response = streamhash_recv_response(conn);
    if (!response) {
        return -1;
    }
    
    int result = (strstr(response, "Rebooting") != NULL) ? 0 : -1;
    free(response);
    return result;
}

int streamhash_shutdown(struct streamhash_connection *conn)
{
    if (streamhash_send_command(conn, "SHUTDOWN") != 0) {
        return -1;
    }
    
    char *response = streamhash_recv_response(conn);
    if (!response) {
        return -1;
    }
    
    int result = (strstr(response, "Shutting down") != NULL) ? 0 : -1;
    free(response);
    return result;
}

char *streamhash_get_stats(struct streamhash_connection *conn)
{
    if (streamhash_send_command(conn, "STATS") != 0) {
        return NULL;
    }
    
    return streamhash_recv_response(conn);
}

char *streamhash_scan_file(struct streamhash_connection *conn, const char *filepath)
{
    if (!conn || !filepath) return NULL;
    
    char command[1024];
    snprintf(command, sizeof(command), "SCAN %s", filepath);
    
    if (streamhash_send_command(conn, command) != 0) {
        return NULL;
    }
    
    return streamhash_recv_response(conn);
}

char *streamhash_scan_stream(struct streamhash_connection *conn, FILE *stream)
{
    if (!conn || !stream) return NULL;
    
    // This would be more complex in a real implementation
    // For now, we'll just return an error
    mprintf(LOGG_ERROR, "SCANSTREAM not implemented yet\n");
    return NULL;
}