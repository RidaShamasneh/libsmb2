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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "smb2.h"
#include "libsmb2.h"

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-request-resume-key-sync <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2fh *fh;
        struct smb2_srv_copychunk_resume_key resume_key;
        int i;
        int rc = 0;

        if (argc < 2) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                return 1;
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_context(smb2);
                return 1;
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, url->server, url->share, url->user) != 0) {
                fprintf(stderr, "smb2_connect_share failed. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out;
        }

        fh = smb2_open(smb2, url->path, O_RDONLY);
        if (fh == NULL) {
                fprintf(stderr, "smb2_open failed. %s\n", smb2_get_error(smb2));
                rc = 10;
                goto out_disconnect;
        }

        if (smb2_request_resume_key(smb2, fh, &resume_key) < 0) {
                fprintf(stderr, "smb2_request_resume_key failed. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out_close;
        }

        printf("Resume key:");
        for (i = 0; i < SMB2_SRV_COPYCHUNK_RESUME_KEY_SIZE; i++) {
                printf("%02x", resume_key.resume_key[i]);
        }
        printf("\n");

out_close:
        smb2_close(smb2, fh);
out_disconnect:
        smb2_disconnect_share(smb2);
out:
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return rc;
}
