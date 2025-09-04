/*
 * Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * StreamHash Hash Module - Hash computation functions
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

#ifndef __STREAMHASH_HASH_H
#define __STREAMHASH_HASH_H

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <json.h>

// Hash result structure
struct streamhash_result {
    // Basic hashes
    char md5[33];
    char sha1[41];
    char sha256[65];
    char sha3_224[57];
    char sha3_256[65];
    char sha3_384[97];
    
    // Fuzzy hashes
    char ssdeep[256];
    char tlsh[256];
    char simhash64[17];
    
    // File properties
    char file_path[1024];
    char file_name[256];
    char original_filename[256];
    char original_extension[32];
    size_t file_size;
    char file_size_readable[32];
    char first_4_bytes[9];
    
    // Analysis metadata
    char analysis_timestamp[32];
    char source_ip[64];
    char source_id[128];
    char scan_item[512];
    char task_id[65];
};

// Hash computation functions
int streamhash_compute_basic_hashes(const char *filepath, struct streamhash_result *result);
int streamhash_compute_fuzzy_hashes(const char *filepath, struct streamhash_result *result);
int streamhash_compute_file_properties(const char *filepath, struct streamhash_result *result);
int streamhash_compute_first_bytes(const char *filepath, struct streamhash_result *result);

// Main hash computation function
int streamhash_compute_all(const char *filepath, const char *source_ip, 
                          const char *source_id, const char *scan_item,
                          struct streamhash_result *result);

// Stream hash computation
int streamhash_compute_stream(FILE *stream, const char *source_ip,
                             const char *source_id, struct streamhash_result *result);

// JSON output functions
json_object *streamhash_result_to_json(const struct streamhash_result *result);
char *streamhash_result_to_json_string(const struct streamhash_result *result);

// Utility functions
void streamhash_result_init(struct streamhash_result *result);
void streamhash_result_cleanup(struct streamhash_result *result);
char *streamhash_generate_task_id(const char *source_ip, const char *source_id, 
                                 const char *scan_item, const char *timestamp);

// Helper functions for readable size
void streamhash_format_size(size_t bytes, char *buffer, size_t buffer_size);

#endif /* __STREAMHASH_HASH_H */