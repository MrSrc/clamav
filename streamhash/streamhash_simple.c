/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Client - Simplified version for testing
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// libclamav
#include "clamav.h"

// common
#include "output.h"
#include "misc.h"

#include "streamhash_client.h"

void simple_help(void)
{
    printf("\nStreamHash Client %s\n", get_version());
    printf("Usage: streamhash [command] [arguments]\n");
    printf("\nCommands:\n");
    printf("  --help              Show this help\n");
    printf("  --version           Show version\n");
    printf("  --ping              Ping daemon\n");
    printf("  --stats             Show daemon statistics\n");
    printf("  --shutdown          Shutdown daemon\n");
    printf("  <filename>          Scan a file\n");
    printf("\nExamples:\n");
    printf("  streamhash --ping\n");
    printf("  streamhash test.txt\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    struct streamhash_connection *conn;
    int ret = 0;
    
    if (argc < 2) {
        simple_help();
        return 1;
    }
    
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        simple_help();
        return 0;
    }
    
    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
        printf("StreamHash %s\n", get_version());
        return 0;
    }
    
    // Connect to daemon
    conn = streamhash_connect(NULL);
    if (!conn) {
        fprintf(stderr, "ERROR: Failed to connect to StreamHash daemon\n");
        return 1;
    }
    
    if (strcmp(argv[1], "--ping") == 0) {
        ret = streamhash_ping(conn);
        if (ret == 0) {
            printf("PONG\n");
        } else {
            fprintf(stderr, "Ping failed\n");
        }
        
    } else if (strcmp(argv[1], "--stats") == 0) {
        char *stats = streamhash_get_stats(conn);
        if (stats) {
            printf("%s", stats);
            free(stats);
        } else {
            fprintf(stderr, "Failed to get statistics\n");
            ret = 1;
        }
        
    } else if (strcmp(argv[1], "--shutdown") == 0) {
        ret = streamhash_shutdown(conn);
        if (ret == 0) {
            printf("Daemon shutdown initiated\n");
        } else {
            fprintf(stderr, "Shutdown failed\n");
        }
        
    } else {
        // Assume it's a file to scan
        char *result = streamhash_scan_file(conn, argv[1]);
        if (result) {
            printf("%s\n", result);
            free(result);
        } else {
            fprintf(stderr, "Failed to scan %s\n", argv[1]);
            ret = 1;
        }
    }
    
    streamhash_disconnect(conn);
    return ret;
}