/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Protocol - Implementation
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "streamhash_protocol.h"

int streamhash_protocol_parse_command(const char *input, char *command, char *args)
{
    if (!input || !command || !args) return -1;
    
    // Simple parsing - split on first space
    const char *space = strchr(input, ' ');
    if (space) {
        size_t cmd_len = space - input;
        strncpy(command, input, cmd_len);
        command[cmd_len] = '\0';
        strcpy(args, space + 1);
    } else {
        strcpy(command, input);
        args[0] = '\0';
    }
    
    return 0;
}

int streamhash_protocol_format_response(char *buffer, size_t buffer_size, const char *response)
{
    if (!buffer || !response) return -1;
    
    snprintf(buffer, buffer_size, "%s\n", response);
    return 0;
}

int streamhash_protocol_format_error(char *buffer, size_t buffer_size, const char *error)
{
    if (!buffer || !error) return -1;
    
    snprintf(buffer, buffer_size, "ERROR: %s\n", error);
    return 0;
}