/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Protocol - Header
 */

#ifndef __STREAMHASH_PROTOCOL_H
#define __STREAMHASH_PROTOCOL_H

// Protocol constants
#define STREAMHASH_PROTOCOL_VERSION "1.0"

// Protocol message types
enum streamhash_msg_type {
    STREAMHASH_MSG_COMMAND,
    STREAMHASH_MSG_RESPONSE,
    STREAMHASH_MSG_ERROR,
    STREAMHASH_MSG_DATA
};

// Protocol functions
int streamhash_protocol_parse_command(const char *input, char *command, char *args);
int streamhash_protocol_format_response(char *buffer, size_t buffer_size, const char *response);
int streamhash_protocol_format_error(char *buffer, size_t buffer_size, const char *error);

#endif /* __STREAMHASH_PROTOCOL_H */