/*
 * smb2_blocking.c
 *
 * Blocking wrappers over libsmb2 async API with a dedicated service thread.
 * Multiple producer threads submit commands; a single service thread owns
 * the smb2_context and drives all I/O, allowing true in-flight concurrency
 * over one TCP connection.
 *
 * Build:
 *   gcc -o smb2_blocking smb2_blocking.c -lsmb2 -lpthread
 *
 *
 *
 * OR:
 *
 *
 *
 *   gcc -o smb2_blocking smb2_blocking.c -I./include -L./build/lib -lsmb2 -lpthread -Wl,-rpath,/home/rida/libsmb2/build/lib -Wall -Wextra -g -Wno-unused-variable -Wno-unused-parameter 
 * 
 *
 *
  To run it:   ./smb2_blocking 127.0.0.1 smbtest test_dir/a test_dir rida $PWD$

usage: ./smb2_blocking <server> <share> <file_path> <watch_dir> [user] [password]

  server     — hostname or IP of the SMB server
  share      — share name (no leading slashes)
  file_path  — path to a file inside the share to read
  watch_dir  — directory inside the share to watch for changes
  user       — (optional) username
  password   — (optional) password

example:
  ./smb2_blocking 127.0.0.1 testshare somefile.txt . guest ""


 */

#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include "libsmb2-private.h"

/* =========================================================================
 * Configuration
 * ========================================================================= */

#define SMB2_MAX_QUEUE      256     /* max pending commands before backpressure */
#define SMB2_POLL_TIMEOUT   1000    /* ms — safety net poll timeout             */
#define SMB2_SERVICE_SLEEP  100     /* us — yield when nothing to poll          */

#if defined(ESP_PLATFORM)
#define SMB2_BLOCKING_NOTIFY_OUTPUT_BUFFER_LENGTH 512
#elif defined(__PS2__)
#define SMB2_BLOCKING_NOTIFY_OUTPUT_BUFFER_LENGTH 4096
#else
#define SMB2_BLOCKING_NOTIFY_OUTPUT_BUFFER_LENGTH 0xffff
#endif

/* =========================================================================
 * smb2_result_t  —  per-command completion state
 * ========================================================================= */

typedef struct {
    pthread_mutex_t  lock;
    pthread_cond_t   cond;
    int              done;      /* set to 1 by service thread callback  */
    int              status;    /* SMB2 status code (0 = success)        */
    void            *data;      /* command-specific result pointer       */
} smb2_result_t;

static void smb2_result_init(smb2_result_t *r) {
    pthread_mutex_init(&r->lock, NULL);
    pthread_cond_init(&r->cond, NULL);
    r->done   = 0;
    r->status = 0;
    r->data   = NULL;
}

static void smb2_result_destroy(smb2_result_t *r) {
    pthread_mutex_destroy(&r->lock);
    pthread_cond_destroy(&r->cond);
}

/* =========================================================================
 * smb2_op_t
 * ========================================================================= */

typedef enum {
    SMB2_OP_CONNECT,
    SMB2_OP_OPEN,
    SMB2_OP_CLOSE,
    SMB2_OP_READ,
    SMB2_OP_WRITE,
    SMB2_OP_STAT,
    SMB2_OP_MKDIR,
    SMB2_OP_UNLINK,
    SMB2_OP_RENAME,
    SMB2_OP_CHANGE_NOTIFY,
    SMB2_OP_CHANGE_NOTIFY_CANCEL,
} smb2_op_t;

/* =========================================================================
 * Change notify types — forward declared for use in smb2_pending_t
 * ========================================================================= */

typedef struct smb2_watch smb2_watch_t;

typedef struct smb2_change_notify {
    uint32_t    action;
    const char *file_name;
} smb2_change_notify_t;

/* =========================================================================
 * smb2_pending_t  —  entry in the submit queue
 * ========================================================================= */

typedef struct smb2_pending {
    smb2_op_t        op;
    smb2_result_t   *result;    /* caller-allocated, lives until done==1 */

    union {
        struct { const char *server; const char *share; const char *user; const char *password; } connect;
        struct { const char *path;   int flags;                           } open;
        struct { struct smb2fh *fh;                                       } close;
        struct { struct smb2fh *fh;  uint8_t *buf; uint32_t len;         } read;
        struct { struct smb2fh *fh;  uint8_t *buf; uint32_t len;         } write;
        struct { const char *path; struct smb2_stat_64 *st;              } stat;
        struct { const char *path;                                        } mkdir;
        struct { const char *path;                                        } unlink;
        struct { const char *oldpath; const char *newpath;               } rename;
        struct { smb2_watch_t *watch;                                    } notify;
        struct { smb2_watch_t *watch;                                    } notify_cancel;
} args;

    struct smb2_pending *next;
} smb2_pending_t;

/* =========================================================================
 * smb2_queue_t  —  thread-safe FIFO
 * ========================================================================= */

typedef struct {
    smb2_pending_t  *head, *tail;
    int              count;
    int              max;
    pthread_mutex_t  lock;
    pthread_cond_t   not_empty;
    pthread_cond_t   not_full;
} smb2_queue_t;

static void queue_init(smb2_queue_t *q, int max) {
    memset(q, 0, sizeof(*q));
    q->max = max;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

/* blocks if queue is full — provides backpressure to producers */
static void queue_push(smb2_queue_t *q, smb2_pending_t *p) {
    pthread_mutex_lock(&q->lock);
    while (q->count >= q->max)
        pthread_cond_wait(&q->not_full, &q->lock);

    p->next = NULL;
    if (q->tail) q->tail->next = p;
    else         q->head       = p;
    q->tail = p;
    q->count++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

/* non-blocking pop — returns NULL if empty */
static smb2_pending_t *queue_try_pop(smb2_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    smb2_pending_t *p = q->head;
    if (p) {
        q->head = p->next;
        if (!q->head) q->tail = NULL;
        q->count--;
        pthread_cond_signal(&q->not_full);
    }
    pthread_mutex_unlock(&q->lock);
    return p;
}

/* =========================================================================
 * smb2_svc_t  —  global service context
 * ========================================================================= */

typedef struct {
    struct smb2_context *smb2;
    smb2_queue_t         queue;
    int                  inflight;
    volatile int         shutdown;
    int                  wakeup_pipe[2];    /* [0]=read end  [1]=write end */
    pthread_t            thread;
} smb2_svc_t;

/* =========================================================================
 * Change notify — callback type and watch handle
 * ========================================================================= */

/*
 * Fired on the service thread when a change arrives.
 */

typedef int (*smb2_notify_cb_t)(
        smb2_change_notify_t      *changes,
        uint32_t                   num_changes,
        void                      *userdata);

struct smb2_watch {
    smb2_svc_t        *svc;
    uint32_t           completion_filter;
    int                watch_tree;
    smb2_notify_cb_t   cb;
    void              *userdata;
    struct smb2fh     *fh;
    volatile int       cancelled;
    pthread_mutex_t    lock;
};

/* =========================================================================
 * Generic callback — fired by service thread inside smb2_service()
 * ========================================================================= */

typedef struct {
    smb2_svc_t    *svc;
    smb2_result_t *result;
} smb2_cb_ctx_t;

static void generic_cb(struct smb2_context *smb2,
                        int status, void *data, void *private_data)
{
    smb2_cb_ctx_t *ctx = private_data;
    smb2_result_t *res = ctx->result;

    res->status = status;
    res->data   = data;

    /* signal completion — done must be written last */
    pthread_mutex_lock(&res->lock);
    res->done = 1;
    pthread_cond_signal(&res->cond);
    pthread_mutex_unlock(&res->lock);

    ctx->svc->inflight--;
    free(ctx);
}

/* =========================================================================
 * Change notify callback
 * ========================================================================= */

typedef struct {
    smb2_svc_t   *svc;
    smb2_watch_t *watch;
} notify_cb_ctx_t;

static uint32_t
count_notify_changes(const struct smb2_file_notify_change_information *fnc)
{
    uint32_t count = 0;

    while (fnc) {
        count++;
        fnc = fnc->next;
    }

    return count;
}

/* forward declaration */
static int dispatch_notify(smb2_svc_t *svc, smb2_watch_t *watch);

static void notify_cb(struct smb2_context *smb2,
                       int status, void *data, void *private_data)
{
    notify_cb_ctx_t *ctx   = private_data;
    smb2_svc_t      *svc   = ctx->svc;
    smb2_watch_t    *watch = ctx->watch;

    if (smb2->hdr.flags & SMB2_FLAGS_ASYNC_COMMAND) {
        fprintf(stdout, "[notify] async_id=%" PRIu64 "\n", smb2->hdr.async.async_id);
    } else {
        fprintf(stdout, "[notify] async_id=<sync>\n");
    }

    if (status == SMB2_STATUS_PENDING) {
        fprintf(stdout, "[notify] STATUS_PENDING\n");

        /* check this call later */
        /* smb2_set_passthrough(smb2, 0); */
        return;
    }

    free(ctx);
    svc->inflight--;

    pthread_mutex_lock(&watch->lock);
    int cancelled = watch->cancelled;
    pthread_mutex_unlock(&watch->lock);

    if (cancelled || status < 0) {
        if (status < 0 && !cancelled)
            fprintf(stderr, "[notify] error: %s\n", smb2_get_error(smb2));

        pthread_mutex_lock(&watch->lock);
        watch->fh = NULL;
        pthread_mutex_unlock(&watch->lock);

        pthread_mutex_destroy(&watch->lock);
        free(watch);
        return;
    }

    /* parse result and fire user callback */
    smb2_change_notify_t *changes = NULL;
    uint32_t              num_changes = 0;
    struct smb2_file_notify_change_information *fnc = NULL;

    if (status == 0 && data) {
        struct smb2_change_notify_reply *reply = data;
        struct smb2_iovec vec;
        struct smb2_file_notify_change_information *cur;
        uint32_t i;

        if (reply->output_buffer_length > 0 && reply->output != NULL) {
            fnc = calloc(1, sizeof(*fnc));
            if (fnc == NULL) {
                fprintf(stderr, "[notify] failed to allocate notify decode state\n");
                status = -ENOMEM;
            } else {
                vec.buf = reply->output;
                vec.len = reply->output_buffer_length;
                if (smb2_decode_filenotifychangeinformation(smb2, fnc, &vec, 0) != 0) {
                    fprintf(stderr, "[notify] failed to decode change notify reply: %s\n", smb2_get_error(smb2));
                    free_smb2_file_notify_change_information(smb2, fnc);
                    fnc = NULL;
                    status = -EIO;
                } else {
                    num_changes = count_notify_changes(fnc);
                    changes = calloc(num_changes, sizeof(*changes));
                    if (changes == NULL) {
                        fprintf(stderr, "[notify] failed to allocate notify change array\n");
                        free_smb2_file_notify_change_information(smb2, fnc);
                        fnc = NULL;
                        num_changes = 0;
                        status = -ENOMEM;
                    } else {
                        cur = fnc;
                        for (i = 0; i < num_changes; i++) {
                            changes[i].action = cur->action;
                            changes[i].file_name = cur->name;
                            cur = cur->next;
                        }
                    }
                }
            }
        }
    }

    watch->cb(changes, num_changes, watch->userdata);

    free(changes);
    if (fnc) {
        free_smb2_file_notify_change_information(smb2, fnc);
    }

    pthread_mutex_lock(&watch->lock);
    watch->fh = NULL;
    pthread_mutex_unlock(&watch->lock);

    pthread_mutex_destroy(&watch->lock);
    free(watch);
}

static int dispatch_notify(smb2_svc_t *svc, smb2_watch_t *watch) {
    pthread_mutex_lock(&watch->lock);
    int            cancelled = watch->cancelled;
    struct smb2fh *fh        = watch->fh;
    pthread_mutex_unlock(&watch->lock);

    if (cancelled || !fh) return 0;

    notify_cb_ctx_t *ctx = malloc(sizeof(*ctx));
    struct smb2_change_notify_request ch_req;
    struct smb2_pdu *pdu;
    if (!ctx) return -1;
    ctx->svc   = svc;
    ctx->watch = watch;

    memset(&ch_req, 0, sizeof(ch_req));
    ch_req.flags = watch->watch_tree ? SMB2_CHANGE_NOTIFY_WATCH_TREE : 0;
    ch_req.output_buffer_length = SMB2_BLOCKING_NOTIFY_OUTPUT_BUFFER_LENGTH;
    memcpy(ch_req.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
    ch_req.completion_filter = watch->completion_filter;

    pdu = smb2_cmd_change_notify_async(svc->smb2, &ch_req, notify_cb, ctx);
    if (pdu == NULL) {
        fprintf(stderr, "[notify] smb2_cmd_change_notify_async failed: %s\n", smb2_get_error(svc->smb2));
        free(ctx);
        return -1;
    }
    smb2_queue_pdu(svc->smb2, pdu);

    svc->inflight++;
    return 0;
}

/* =========================================================================
 * Dispatch — called only from service thread
 * ========================================================================= */

static int dispatch(smb2_svc_t *svc, smb2_pending_t *p) {
    int rc = 0;

    switch (p->op) {

        case SMB2_OP_CONNECT: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;

            if (p->args.connect.password)
                smb2_set_password(svc->smb2, p->args.connect.password);
            if (p->args.connect.user)
                smb2_set_user(svc->smb2, p->args.connect.user);
            smb2_set_domain(svc->smb2, "");                        /* empty = workgroup */
            smb2_set_security_mode(svc->smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
            smb2_set_authentication(svc->smb2, SMB2_SEC_NTLMSSP);  /* skip Kerberos */
            rc = smb2_connect_share_async(svc->smb2,
                     p->args.connect.server,
                     p->args.connect.share,
                     p->args.connect.user,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_OPEN: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;
            rc = smb2_open_async(svc->smb2,
                     p->args.open.path,
                     p->args.open.flags,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_CLOSE: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;
            rc = smb2_close_async(svc->smb2,
                     p->args.close.fh,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_READ: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;
            rc = smb2_read_async(svc->smb2,
                     p->args.read.fh,
                     p->args.read.buf,
                     p->args.read.len,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_WRITE: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;
            rc = smb2_write_async(svc->smb2,
                     p->args.write.fh,
                     p->args.write.buf,
                     p->args.write.len,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_STAT: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;
            rc = smb2_stat_async(svc->smb2,
                     p->args.stat.path,
                     p->args.stat.st,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_MKDIR: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;
            rc = smb2_mkdir_async(svc->smb2,
                     p->args.mkdir.path,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_UNLINK: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;
            rc = smb2_unlink_async(svc->smb2,
                     p->args.unlink.path,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_RENAME: {
            smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return -1;
            ctx->svc    = svc;
            ctx->result = p->result;
            rc = smb2_rename_async(svc->smb2,
                     p->args.rename.oldpath,
                     p->args.rename.newpath,
                     generic_cb, ctx);
            if (rc < 0) { free(ctx); return -1; }
            svc->inflight++;
            break;
        }

        case SMB2_OP_CHANGE_NOTIFY: {
            smb2_watch_t *watch = p->args.notify.watch;

            pthread_mutex_lock(&watch->lock);
            struct smb2fh *fh = watch->fh;
            pthread_mutex_unlock(&watch->lock);

            if (!fh) {
                fprintf(stderr, "[notify] missing watch directory handle\n");
                pthread_mutex_lock(&p->result->lock);
                p->result->status = -1;
                p->result->done   = 1;
                pthread_cond_signal(&p->result->cond);
                pthread_mutex_unlock(&p->result->lock);
                return -1;
            }
            /* signal caller: registration succeeded */
            pthread_mutex_lock(&p->result->lock);
            p->result->status = 0;
            p->result->data   = watch;
            p->result->done   = 1;
            pthread_cond_signal(&p->result->cond);
            pthread_mutex_unlock(&p->result->lock);

            /* arm the first async change notify */
            dispatch_notify(svc, watch);
            rc = 0;
            break;
        }

        case SMB2_OP_CHANGE_NOTIFY_CANCEL: {
            smb2_watch_t *watch = p->args.notify_cancel.watch;

            pthread_mutex_lock(&watch->lock);
            watch->cancelled = 1;
            pthread_mutex_unlock(&watch->lock);

            /*
             * Actual cleanup (free) happens in notify_cb when the server
             * responds to the now-cancelled request.
             */
            pthread_mutex_lock(&p->result->lock);
            p->result->status = 0;
            p->result->done   = 1;
            pthread_cond_signal(&p->result->cond);
            pthread_mutex_unlock(&p->result->lock);
            rc = 0;
            break;
        }

        default:
            rc = -1;
            break;
    }

    return rc;
}

/* =========================================================================
 * Service thread
 * ========================================================================= */

static void wakeup_service(smb2_svc_t *svc) {
    char b = 1;
    write(svc->wakeup_pipe[1], &b, 1);
}

static void *service_thread(void *arg) {
    smb2_svc_t *svc = arg;

    while (!svc->shutdown) {

        /* 1. drain submit queue — dispatch all pending ops onto the wire */
        smb2_pending_t *p;
        while ((p = queue_try_pop(&svc->queue)) != NULL) {
            if (dispatch(svc, p) < 0) {
                /* dispatch failed and did not signal result — signal error now
                 * (CHANGE_NOTIFY and CHANGE_NOTIFY_CANCEL signal inside dispatch) */
                if (p->op != SMB2_OP_CHANGE_NOTIFY &&
                    p->op != SMB2_OP_CHANGE_NOTIFY_CANCEL) {
                    pthread_mutex_lock(&p->result->lock);
                    p->result->status = -1;
                    p->result->done   = 1;
                    pthread_cond_signal(&p->result->cond);
                    pthread_mutex_unlock(&p->result->lock);
                }
            }
            free(p);
        }

        /* 2. build poll set */
        int smb2_fd     = smb2_get_fd(svc->smb2);
        int smb2_events = smb2_which_events(svc->smb2);

        struct pollfd pfds[2];
        int nfds = 0;

        if (smb2_fd >= 0 && smb2_events) {
            pfds[nfds].fd     = smb2_fd;
            pfds[nfds].events = smb2_events;
            nfds++;
        }

        /* always watch wakeup pipe so new submissions interrupt poll() */
        pfds[nfds].fd      = svc->wakeup_pipe[0];
        pfds[nfds].events  = POLLIN;
        nfds++;

        /* 3. poll — timeout keeps us alive even if wakeup_pipe is quiet */
        int timeout_ms = (svc->inflight > 0 || smb2_events) ? SMB2_POLL_TIMEOUT : 100;
        int ret = poll(pfds, nfds, timeout_ms);
        if (ret < 0 && errno != EINTR) {
            fprintf(stderr, "[svc] poll error: %s\n", strerror(errno));
            break;
        }

        /* 4. drain wakeup pipe */
        if (pfds[nfds - 1].revents & POLLIN) {
            char buf[64];
            read(svc->wakeup_pipe[0], buf, sizeof(buf));
        }

        /* 5. service smb2 — all pending callbacks fire here */
        if (smb2_fd >= 0 && nfds > 1 && pfds[0].revents) {
            if (smb2_service(svc->smb2, pfds[0].revents) < 0) {
                fprintf(stderr, "[svc] smb2_service error: %s\n", smb2_get_error(svc->smb2));
                break;
            }
        } else if (smb2_fd >= 0 && nfds == 1 && pfds[0].fd == smb2_fd
                   && pfds[0].revents) {
            /* only smb2 fd registered (wakeup_pipe check above handles nfds) */
            if (smb2_service(svc->smb2, pfds[0].revents) < 0) {
                fprintf(stderr, "[svc] smb2_service error: %s\n", smb2_get_error(svc->smb2));
                break;
            }
        }
    }

    fprintf(stderr, "[svc] service thread exiting\n");
    return NULL;
}

/* =========================================================================
 * Internal submit + wait helper
 * ========================================================================= */

/*
 * submit_and_wait()
 *
 * Called by every blocking wrapper:
 *   1. pushes the pending op onto the queue (may block on backpressure)
 *   2. wakes the service thread
 *   3. waits on the per-result condvar until done==1
 *   4. returns the SMB2 status code
 */
static int submit_and_wait(smb2_svc_t *svc,
                            smb2_pending_t *p,
                            smb2_result_t  *res)
{
    smb2_result_init(res);
    p->result = res;

    queue_push(&svc->queue, p);   /* may block if queue is full */
    wakeup_service(svc);

    /* wait for service thread to complete this op */
    pthread_mutex_lock(&res->lock);
    while (!res->done)
        pthread_cond_wait(&res->cond, &res->lock);
    pthread_mutex_unlock(&res->lock);

    int status = res->status;
    smb2_result_destroy(res);
    return status;
}

/* =========================================================================
 * Public blocking wrappers
 * ========================================================================= */

/*
 * smb2_svc_init()
 *
 * Creates the smb2 context, starts the service thread.
 * Call once at startup before any blocking wrappers.
 */
smb2_svc_t *smb2_svc_init(void) {
    smb2_svc_t *svc = calloc(1, sizeof(*svc));
    if (!svc) return NULL;

    svc->smb2 = smb2_init_context();
    if (!svc->smb2) { free(svc); return NULL; }

    queue_init(&svc->queue, SMB2_MAX_QUEUE);

    if (pipe(svc->wakeup_pipe) < 0) {
        smb2_destroy_context(svc->smb2);
        free(svc);
        return NULL;
    }

    if (pthread_create(&svc->thread, NULL, service_thread, svc) != 0) {
        close(svc->wakeup_pipe[0]);
        close(svc->wakeup_pipe[1]);
        smb2_destroy_context(svc->smb2);
        free(svc);
        return NULL;
    }

    return svc;
}

/*
 * smb2_svc_shutdown()
 *
 * Signals the service thread to exit and waits for it.
 */
void smb2_svc_shutdown(smb2_svc_t *svc) {
    svc->shutdown = 1;
    wakeup_service(svc);
    pthread_join(svc->thread, NULL);
    smb2_disconnect_share(svc->smb2);
    smb2_destroy_context(svc->smb2);
    close(svc->wakeup_pipe[0]);
    close(svc->wakeup_pipe[1]);
    free(svc);
}

/* -------------------------------------------------------------------------
 * connect
 * ---------------------------------------------------------------------- */
int smb2_blocking_connect(smb2_svc_t  *svc,
                           const char  *server,
                           const char  *share,
                           const char  *user,
                           const char  *password)
{
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op                     = SMB2_OP_CONNECT;
    p->args.connect.server    = server;
    p->args.connect.share     = share;
    p->args.connect.user      = user;
    p->args.connect.password  = password;   /* NULL = try anonymous / Kerberos */

    return submit_and_wait(svc, p, &res);
}

/* -------------------------------------------------------------------------
 * open  — returns smb2fh* via out_fh, or NULL on error
 * ---------------------------------------------------------------------- */
int smb2_blocking_open(smb2_svc_t   *svc,
                        const char   *path,
                        int           flags,
                        struct smb2fh **out_fh)
{
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op             = SMB2_OP_OPEN;
    p->args.open.path = path;
    p->args.open.flags = flags;

    int rc = submit_and_wait(svc, p, &res);
    if (out_fh) *out_fh = (rc == 0) ? (struct smb2fh *)res.data : NULL;
    return rc;
}

/* -------------------------------------------------------------------------
 * close
 * ---------------------------------------------------------------------- */
int smb2_blocking_close(smb2_svc_t *svc, struct smb2fh *fh) {
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op           = SMB2_OP_CLOSE;
    p->args.close.fh = fh;

    return submit_and_wait(svc, p, &res);
}

/* -------------------------------------------------------------------------
 * read  — returns bytes read (>=0) or negative error
 * ---------------------------------------------------------------------- */
int smb2_blocking_read(smb2_svc_t    *svc,
                        struct smb2fh *fh,
                        uint8_t       *buf,
                        uint32_t       len)
{
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op           = SMB2_OP_READ;
    p->args.read.fh  = fh;
    p->args.read.buf = buf;
    p->args.read.len = len;

    return submit_and_wait(svc, p, &res);
}

/* -------------------------------------------------------------------------
 * write  — returns bytes written (>=0) or negative error
 * ---------------------------------------------------------------------- */
int smb2_blocking_write(smb2_svc_t    *svc,
                         struct smb2fh *fh,
                         uint8_t       *buf,
                         uint32_t       len)
{
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op            = SMB2_OP_WRITE;
    p->args.write.fh  = fh;
    p->args.write.buf = buf;
    p->args.write.len = len;

    return submit_and_wait(svc, p, &res);
}

/* -------------------------------------------------------------------------
 * stat  — fills caller-supplied smb2_stat_64 struct
 * ---------------------------------------------------------------------- */
int smb2_blocking_stat(smb2_svc_t        *svc,
                        const char        *path,
                        struct smb2_stat_64 *st)
{
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op             = SMB2_OP_STAT;
    p->args.stat.path = path;
    p->args.stat.st   = st;   /* service thread fills this in-place */

    return submit_and_wait(svc, p, &res);
}

/* -------------------------------------------------------------------------
 * mkdir
 * ---------------------------------------------------------------------- */
int smb2_blocking_mkdir(smb2_svc_t *svc, const char *path) {
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op             = SMB2_OP_MKDIR;
    p->args.mkdir.path = path;

    return submit_and_wait(svc, p, &res);
}

/* -------------------------------------------------------------------------
 * unlink
 * ---------------------------------------------------------------------- */
int smb2_blocking_unlink(smb2_svc_t *svc, const char *path) {
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op              = SMB2_OP_UNLINK;
    p->args.unlink.path = path;

    return submit_and_wait(svc, p, &res);
}

/* -------------------------------------------------------------------------
 * rename
 * ---------------------------------------------------------------------- */
int smb2_blocking_rename(smb2_svc_t *svc,
                          const char *oldpath,
                          const char *newpath)
{
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op                  = SMB2_OP_RENAME;
    p->args.rename.oldpath = oldpath;
    p->args.rename.newpath = newpath;

    return submit_and_wait(svc, p, &res);
}

/* =========================================================================
 * Public API — change notify
 * ========================================================================= */

/*
 * smb2_blocking_watch()
 *
 * Registers a change notify watch on a directory.
 * Returns an opaque smb2_watch_t* handle on success, NULL on failure.
 *
 * completion_filter:  SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME  |
 *                     SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_DIR_NAME   |
 *                     SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_WRITE | ... (see smb2.h)
 * watch_tree:         1 = recursive, 0 = top-level directory only
 *
 * The callback fires on the SERVICE THREAD — keep it short and
 * non-blocking. Do not call smb2_blocking_* from inside the callback.
 *
 */
smb2_watch_t *smb2_blocking_watch(smb2_svc_t       *svc,
                                   struct smb2fh    *dir_handle,
                                   uint32_t          completion_filter,
                                   int               watch_tree,
                                   smb2_notify_cb_t  cb,
                                   void             *userdata)
{
    smb2_watch_t *watch = calloc(1, sizeof(*watch));
    if (!watch) return NULL;

    watch->svc               = svc;
    watch->completion_filter = completion_filter;
    watch->watch_tree        = watch_tree;
    watch->cb                = cb;
    watch->userdata          = userdata;
    watch->cancelled         = 0;
    watch->fh                = dir_handle;
    pthread_mutex_init(&watch->lock, NULL);

    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op                = SMB2_OP_CHANGE_NOTIFY;
    p->args.notify.watch = watch;

    int rc = submit_and_wait(svc, p, &res);
    if (rc < 0) {
        pthread_mutex_destroy(&watch->lock);
        free(watch);
        return NULL;
    }

    return watch;
}

/*
 * smb2_blocking_unwatch()
 *
 * Cancels an active watch. The watch handle is freed asynchronously
 * once the server responds to the cancelled request.
 * Do NOT use the watch handle after calling this.
 */
int smb2_blocking_unwatch(smb2_svc_t *svc, smb2_watch_t *watch) {
    smb2_pending_t *p = calloc(1, sizeof(*p));
    smb2_result_t   res;

    p->op                         = SMB2_OP_CHANGE_NOTIFY_CANCEL;
    p->args.notify_cancel.watch   = watch;

    return submit_and_wait(svc, p, &res);
}

/* =========================================================================
 * Demo — producer threads + change notify watcher
 * ========================================================================= */

#define NUM_PRODUCERS   111
#define READS_PER_PROD  111
#define READ_BUF_SIZE   65536

typedef struct {
    smb2_svc_t  *svc;
    int          id;
    const char  *path;
} producer_args_t;

static void *producer_thread(void *arg) {
    producer_args_t *a   = arg;
    smb2_svc_t      *svc = a->svc;
    unsigned int     seed = (unsigned int)(time(NULL) ^ (a->id * 1103515245u));

    struct smb2fh *fh = NULL;
    int rc = smb2_blocking_open(svc, a->path, O_RDWR, &fh);
    if (rc < 0 || !fh) {
        fprintf(stderr, "[prod %d] open failed: %d\n", a->id, rc);
        return NULL;
    }
    fprintf(stderr, "[prod %d] opened %s\n", a->id, a->path);

    uint8_t *buf = malloc(READ_BUF_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "[prod %d] buffer allocation failed\n", a->id);
        smb2_blocking_close(svc, fh);
        return NULL;
    }

    for (int i = 0; i < READS_PER_PROD; i++) {
        for (uint32_t j = 0; j < READ_BUF_SIZE; j++) {
            buf[j] = (uint8_t)(rand_r(&seed) & 0xff);
        }

        int n = smb2_blocking_write(svc, fh, buf, READ_BUF_SIZE);
        if (n < 0) {
            fprintf(stderr, "[prod %d] write %d failed: %d\n", a->id, i, n);
            break;
        }
        fprintf(stderr, "[prod %d] write %d: wrote %d bytes\n", a->id, i, n);
    }

    free(buf);
    smb2_blocking_close(svc, fh);
    fprintf(stderr, "[prod %d] done\n", a->id);
    return NULL;
}

/* Change notify callback — fired on service thread */
static int on_change(smb2_change_notify_t      *changes,
                     uint32_t                   num_changes,
                     void                      *userdata)
{
    (void)userdata;

    if (num_changes == 0) {
        fprintf(stderr, "[notify] buffer overflow — too many changes\n");
        return 0;
    }

        fprintf(stderr, "[notify] %u change(s):\n", num_changes);
        for (uint32_t i = 0; i < num_changes; i++) {
            const char *action_str = "UNKNOWN";
            switch (changes[i].action) {
            case SMB2_NOTIFY_CHANGE_FILE_ACTION_ADDED:            action_str = "ADDED";             break;
            case SMB2_NOTIFY_CHANGE_FILE_ACTION_REMOVED:          action_str = "REMOVED";           break;
            case SMB2_NOTIFY_CHANGE_FILE_ACTION_MODIFIED:         action_str = "MODIFIED";          break;
            case SMB2_NOTIFY_CHANGE_FILE_ACTION_RENAMED_OLD_NAME: action_str = "RENAMED_OLD_NAME";  break;
            case SMB2_NOTIFY_CHANGE_FILE_ACTION_RENAMED_NEW_NAME: action_str = "RENAMED_NEW_NAME";  break;
            }
        fprintf(stderr, "  [%u] action=%-20s  name=%s\n",
                i, action_str,
                changes[i].file_name ? changes[i].file_name : "(null)");
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr,
            "usage: %s <server> <share> <file_path> <watch_dir> [user] [password]\n"
            "\n"
            "  server     — hostname or IP of the SMB server\n"
            "  share      — share name (no leading slashes)\n"
            "  file_path  — path to a file inside the share to read\n"
            "  watch_dir  — directory inside the share to watch for changes\n"
            "  user       — (optional) username\n"
            "  password   — (optional) password\n"
            "\n"
            "example:\n"
            "  %s 127.0.0.1 testshare somefile.txt . guest \"\"\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *server    = argv[1];
    const char *share     = argv[2];
    const char *file_path = argv[3];
    const char *watch_dir = argv[4];
    const char *user      = (argc >= 6) ? argv[5] : NULL;
    const char *password  = (argc >= 7) ? argv[6] : NULL;

    /* init service context + start service thread */
    smb2_svc_t *svc = smb2_svc_init();
    if (!svc) { fprintf(stderr, "smb2_svc_init failed\n"); return 1; }

    /* connect (blocking — must complete before producers start) */
    int rc = smb2_blocking_connect(svc, server, share, user, password);
    if (rc < 0) {
        fprintf(stderr, "connect failed: %s\n", smb2_get_error(svc->smb2));
        smb2_svc_shutdown(svc);
        return 1;
    }
    fprintf(stderr, "connected to \\\\%s\\%s\n", server, share);

    /* register change notify on watch_dir before producers start */
    uint32_t filter = SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME  |
                      SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_DIR_NAME   |
                      SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_WRITE |
                      SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_ACCESS |
                      SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_ATTRIBUTES |
                      SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_SIZE;
    struct smb2fh *watch_fh = NULL;

#ifdef O_DIRECTORY
    rc = smb2_blocking_open(svc, watch_dir, O_DIRECTORY, &watch_fh);
#else
    rc = smb2_blocking_open(svc, watch_dir, 0, &watch_fh);
#endif
    if (rc < 0 || !watch_fh) {
        fprintf(stderr, "[main] failed to open watch directory '%s': %d\n",
                watch_dir, rc);
        smb2_svc_shutdown(svc);
        return 1;
    }

    /* check later */
    smb2_set_passthrough(svc->smb2, 0);

    smb2_watch_t *watch = smb2_blocking_watch(svc, watch_fh, filter, /*watch_tree=*/0, on_change, NULL);

    if (!watch)
        fprintf(stderr, "[main] change notify registration failed — continuing without watch\n");
    else
        fprintf(stderr, "[main] watching '%s' for changes\n", watch_dir);

    /* launch producer threads */
    pthread_t       threads[NUM_PRODUCERS];
    producer_args_t args[NUM_PRODUCERS];

    for (int i = 0; i < NUM_PRODUCERS; i++) {
        args[i].svc  = svc;
        args[i].id   = i;
        args[i].path = file_path;
        pthread_create(&threads[i], NULL, producer_thread, &args[i]);
    }

    for (int i = 0; i < NUM_PRODUCERS; i++)
        pthread_join(threads[i], NULL);

    fprintf(stderr, "[main] all producers done — press Enter to stop watching\n");
    getchar();

    if (watch_fh)
        smb2_blocking_close(svc, watch_fh);

    sleep(1);   /* let cancel propagate before tearing down */
    smb2_svc_shutdown(svc);
    fprintf(stderr, "shutdown complete\n");
    return 0;
}
