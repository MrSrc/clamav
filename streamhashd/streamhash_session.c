/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Session Management - Implementation
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "streamhash_session.h"
#include "streamhash_server.h"

void streamhash_session_init(struct streamhash_session *session)
{
    if (!session) return;
    // Session initialization is handled in the main server code
}

void streamhash_session_cleanup(struct streamhash_session *session)
{
    if (!session) return;
    // Session cleanup is handled in the session thread
}