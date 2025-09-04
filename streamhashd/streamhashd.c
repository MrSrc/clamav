/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Daemon - A hash computation service daemon
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <locale.h>

#include "target.h"

// libclamav
#include "clamav.h"
#include "others.h"

// common
#include "output.h"
#include "optparser.h"
#include "misc.h"

#include "streamhash_server.h"

short debug_mode = 0, logok = 0;
short foreground = -1;

static void help(void)
{
    printf("\n");
    printf("                      StreamHash: Hash Service Daemon %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2025 Cisco Systems, Inc.\n");
    printf("\n");
    printf("    streamhashd [options]\n");
    printf("\n");
    printf("    --help                   -h             Show this help\n");
    printf("    --version                -V             Show version number\n");
    printf("    --debug                  -d             Enable debug mode\n");
    printf("    --config-file=FILE       -c FILE        Read configuration from FILE\n");
    printf("    --foreground             -F             Run in foreground\n");
    printf("\n");
}

static void streamhash_print_version(void)
{
    printf("StreamHash %s\n", get_version());
}

int main(int argc, char **argv)
{
    struct optstruct *opts;
    char *cfgfile;
    int ret = 0;
    int j;

    printf("StreamHash Hash Service Daemon %s\n", get_version());
    printf("(C) 2025 Cisco Systems, Inc.\n\n");

    if ((opts = optparse(NULL, argc, argv, 1, OPT_CLAMD, 0, NULL)) == NULL) {
        mprintf(LOGG_ERROR, "Can't parse command line options\n");
        return 1;
    }

    if (optget(opts, "help")->enabled) {
        optfree(opts);
        help();
        return 0;
    }

    if (optget(opts, "version")->enabled) {
        optfree(opts);
        streamhash_print_version();
        return 0;
    }

    if (optget(opts, "debug")->enabled) {
        debug_mode = 1;
    }

    /* check foreground option from command line */
    for (j = 0; j < argc; j++) {
        if ((memcmp(argv[j], "--foreground", 12) == 0) || (memcmp(argv[j], "-F", 2) == 0)) {
            foreground = 1;
            break;
        }
    }

    if (foreground == -1) {
        foreground = 0; // Default to background
    }

    /* parse the config file */
    cfgfile = optget(opts, "config-file")->strarg;
    if (cfgfile == NULL) {
        cfgfile = "/usr/local/etc/streamhashd.conf";
    }

    printf("Reading configuration from %s\n", cfgfile);

    /* initialize logging */
    logg_verbose = mprintf_verbose = debug_mode;

    /* initialize the server */
    ret = streamhash_server_init(opts);
    if (ret != 0) {
        mprintf(LOGG_ERROR, "Failed to initialize StreamHash server\n");
        optfree(opts);
        return ret;
    }

    if (!foreground) {
        printf("Forking into background...\n");
        if (daemon(0, 0) == -1) {
            mprintf(LOGG_ERROR, "Failed to daemonize: %s\n", strerror(errno));
            optfree(opts);
            return 1;
        }
    }

    mprintf(LOGG_INFO, "StreamHash daemon starting up...\n");

    /* start the server */
    ret = streamhash_server_run();

    /* cleanup */
    streamhash_server_cleanup();
    optfree(opts);

    mprintf(LOGG_INFO, "StreamHash daemon shutting down\n");
    return ret;
}