/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Client - Command-line interface for StreamHash daemon
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

// libclamav
#include "clamav.h"

// common
#include "output.h"
#include "misc.h"
#include "optparser.h"

#include "streamhash_client.h"

void help(void)
{
    printf("\n");
    printf("                      StreamHash Client %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2025 Cisco Systems, Inc.\n");
    printf("\n");
    printf("    streamhash [options] [file/directory...]\n");
    printf("\n");
    printf("    --help                   -h             Show this help\n");
    printf("    --version                -V             Show version number\n");
    printf("    --verbose                -v             Be verbose\n");
    printf("    --quiet                  -q             Be quiet\n");
    printf("    --config-file=FILE       -c FILE        Read configuration from FILE\n");
    printf("    --ping                   -p             Ping daemon\n");
    printf("    --reload                 -r             Reload daemon\n");
    printf("    --shutdown                              Shutdown daemon\n");
    printf("    --stats                                 Show daemon statistics\n");
    printf("    --stream                                Use SCANSTREAM command\n");
    printf("    --fdpass                                Pass file descriptor\n");
    printf("    --allmatch                              Continue scanning after match\n");
    printf("    --no-summary                            Don't print summary\n");
    printf("\n");
    printf("Examples:\n");
    printf("    streamhash file.exe           # Scan a single file\n");
    printf("    streamhash /home/user/docs/   # Scan a directory\n");
    printf("    streamhash --ping             # Test connection to daemon\n");
    printf("    streamhash --stats            # Show daemon statistics\n");
    printf("\n");
}

static void print_server_version(void)
{
    struct streamhash_connection *conn = streamhash_connect(NULL);
    if (!conn) {
        printf("ClamAV %s\n", get_version());
        return;
    }
    
    char *version = streamhash_get_version(conn);
    if (version) {
        printf("%s\n", version);
        free(version);
    } else {
        printf("ClamAV %s\n", get_version());
    }
    
    streamhash_disconnect(conn);
}

int main(int argc, char **argv)
{
    int ret = 0;
    struct optstruct *opts;
    time_t start_time, end_time;
    int i;
    
    if ((opts = optparse(NULL, argc, argv, 1, OPT_CLAMDSCAN, OPT_CLAMSCAN, NULL)) == NULL) {
        mprintf(LOGG_ERROR, "Can't parse command line options\n");
        return 2;
    }
    
    if (optget(opts, "help")->enabled) {
        optfree(opts);
        help();
        return 0;
    }
    
    if (optget(opts, "verbose")->enabled) {
        mprintf_verbose = 1;
        logg_verbose = 1;
    }
    
    if (optget(opts, "quiet")->enabled) {
        mprintf_quiet = 1;
    }
    
    if (optget(opts, "version")->enabled) {
        print_server_version();
        optfree(opts);
        return 0;
    }
    
    // Connect to daemon
    struct streamhash_connection *conn = streamhash_connect(opts);
    if (!conn) {
        mprintf(LOGG_ERROR, "Failed to connect to StreamHash daemon\n");
        optfree(opts);
        return 1;
    }
    
    start_time = time(NULL);
    
    // Handle special commands
    if (optget(opts, "ping")->enabled) {
        ret = streamhash_ping(conn);
        if (ret == 0) {
            mprintf(LOGG_INFO, "PONG\n");
        } else {
            mprintf(LOGG_ERROR, "Ping failed\n");
        }
        
    } else if (optget(opts, "reload")->enabled) {
        ret = streamhash_reload(conn);
        if (ret == 0) {
            mprintf(LOGG_INFO, "Daemon reloaded\n");
        } else {
            mprintf(LOGG_ERROR, "Reload failed\n");
        }
        
    } else if (optget(opts, "shutdown")->enabled) {
        ret = streamhash_shutdown(conn);
        if (ret == 0) {
            mprintf(LOGG_INFO, "Daemon shutdown initiated\n");
        } else {
            mprintf(LOGG_ERROR, "Shutdown failed\n");
        }
        
    } else if (optget(opts, "stats")->enabled) {
        char *stats = streamhash_get_stats(conn);
        if (stats) {
            printf("%s", stats);
            free(stats);
        } else {
            mprintf(LOGG_ERROR, "Failed to get statistics\n");
            ret = 1;
        }
        
    } else {
        // Scan files/directories
        int infected = 0, errors = 0, scanned = 0;
        
        if (argc <= 1 || !argv[1]) {
            mprintf(LOGG_ERROR, "No files specified for scanning\n");
            ret = 1;
        } else {
            for (i = 1; i < argc; i++) {
                if (argv[i][0] == '-') continue; // Skip options
                
                mprintf(LOGG_INFO, "Scanning %s...\n", argv[i]);
                
                char *result = streamhash_scan_file(conn, argv[i]);
                if (result) {
                    printf("%s\n", result);
                    free(result);
                    scanned++;
                } else {
                    mprintf(LOGG_ERROR, "Failed to scan %s\n", argv[i]);
                    errors++;
                }
            }
        }
        
        if (!optget(opts, "no-summary")->enabled) {
            end_time = time(NULL);
            printf("\n----------- SCAN SUMMARY -----------\n");
            printf("Files scanned: %d\n", scanned);
            printf("Infected files: %d\n", infected);
            printf("Errors: %d\n", errors);
            printf("Time: %.3f sec (%d files/sec)\n", 
                   (double)(end_time - start_time),
                   scanned > 0 ? (int)(scanned / (double)(end_time - start_time)) : 0);
        }
    }
    
    streamhash_disconnect(conn);
    optfree(opts);
    return ret;
}