/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Client Library - Header
 */

#ifndef __STREAMHASH_CLIENT_H
#define __STREAMHASH_CLIENT_H

// common
#include "optparser.h"

// Connection structure
struct streamhash_connection {
    int socket;
    char server_host[256];
    int server_port;
    char buffer[8192];
};

// Connection management
struct streamhash_connection *streamhash_connect(const struct optstruct *opts);
void streamhash_disconnect(struct streamhash_connection *conn);

// Commands
int streamhash_ping(struct streamhash_connection *conn);
char *streamhash_get_version(struct streamhash_connection *conn);
int streamhash_reload(struct streamhash_connection *conn);
int streamhash_shutdown(struct streamhash_connection *conn);
char *streamhash_get_stats(struct streamhash_connection *conn);
char *streamhash_scan_file(struct streamhash_connection *conn, const char *filepath);
char *streamhash_scan_stream(struct streamhash_connection *conn, FILE *stream);

// Internal communication functions
int streamhash_send_command(struct streamhash_connection *conn, const char *command);
char *streamhash_recv_response(struct streamhash_connection *conn);

#endif /* __STREAMHASH_CLIENT_H */