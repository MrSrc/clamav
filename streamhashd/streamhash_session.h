/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Session Management - Header
 */

#ifndef __STREAMHASH_SESSION_H
#define __STREAMHASH_SESSION_H

#include <time.h>
#include <pthread.h>

struct streamhash_session;

// Session management functions
void streamhash_session_init(struct streamhash_session *session);
void streamhash_session_cleanup(struct streamhash_session *session);

#endif /* __STREAMHASH_SESSION_H */