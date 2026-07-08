/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-request-resume-key-sync <source-url> <destination-url>\n\n"
                "Both URLs must point to the same server/share.\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

static int same_or_null(const char *a, const char *b)
{
        if (a == NULL || b == NULL) {
                return a == b;
        }

        return strcmp(a, b) == 0;
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *src_url;
        struct smb2_url *dst_url;
        struct smb2fh *srcfh;
        struct smb2fh *dstfh;
        struct smb2_stat_64 st;
        struct smb2_srv_copychunk chunk;
        struct smb2_srv_copychunk_reply reply;
        int rc = 0;

        if (argc < 3) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                return 1;
        }

        src_url = smb2_parse_url(smb2, argv[1]);
        if (src_url == NULL) {
                fprintf(stderr, "Failed to parse source url: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_context(smb2);
                return 1;
        }

        dst_url = smb2_parse_url(smb2, argv[2]);
        if (dst_url == NULL) {
                fprintf(stderr, "Failed to parse destination url: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_url(src_url);
                smb2_destroy_context(smb2);
                return 1;
        }

        if (!same_or_null(src_url->domain, dst_url->domain) ||
            !same_or_null(src_url->server, dst_url->server) ||
            !same_or_null(src_url->share, dst_url->share) ||
            !same_or_null(src_url->user, dst_url->user)) {
                fprintf(stderr, "Source and destination URLs must use the same domain, server, share, and user\n");
                rc = 1;
                goto out;
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, src_url->server, src_url->share, src_url->user) != 0) {
                fprintf(stderr, "smb2_connect_share failed. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out;
        }

        srcfh = smb2_open(smb2, src_url->path, O_RDONLY);
        if (srcfh == NULL) {
                fprintf(stderr, "Failed to open source file. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out_disconnect;
        }

        if (smb2_fstat(smb2, srcfh, &st) < 0) {
                fprintf(stderr, "smb2_fstat failed. %s\n", smb2_get_error(smb2));
                rc = 10;
                goto out_close_src;
        }

        dstfh = smb2_open(smb2, dst_url->path, O_WRONLY | O_CREAT | O_TRUNC);
        if (dstfh == NULL) {
                fprintf(stderr, "Failed to open destination file. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out_close_src;
        }

        if (st.smb2_size == 0) {
                printf("Copied 0 bytes\n");
                goto out_close_dst;
        }

        memset(&chunk, 0, sizeof(chunk));
        memset(&reply, 0, sizeof(reply));
        chunk.source_offset = 0;
        chunk.target_offset = 0;
        chunk.length = (uint32_t)st.smb2_size;

        if ((uint64_t)chunk.length != st.smb2_size) {
                fprintf(stderr, "Source file is too large for this simple single-chunk example: %" PRIu64 " bytes\n",
                        st.smb2_size);
                rc = 1;
                goto out_close_dst;
        }

        if (smb2_server_side_copy(smb2, srcfh, dstfh, &chunk, 1, &reply) < 0) {
                fprintf(stderr, "smb2_server_side_copy failed. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out_close_dst;
        }

        printf("Copied %" PRIu64 " bytes\n", st.smb2_size);
        printf("Chunks written:%" PRIu32 "\n", reply.chunks_written);
        printf("Chunk bytes written:%" PRIu32 "\n", reply.chunk_bytes_written);
        printf("Total bytes written:%" PRIu32 "\n", reply.total_bytes_written);

out_close_dst:
        smb2_close(smb2, dstfh);
out_close_src:
        smb2_close(smb2, srcfh);
out_disconnect:
        smb2_disconnect_share(smb2);
out:
        smb2_destroy_url(dst_url);
        smb2_destroy_url(src_url);
        smb2_destroy_context(smb2);

        return rc;
}
