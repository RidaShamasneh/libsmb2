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
 */

#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

/* =========================================================================
 * Configuration
 * ========================================================================= */

#define SMB2_MAX_QUEUE      256     /* max pending commands before backpressure */
#define SMB2_POLL_TIMEOUT   1000    /* ms — safety net poll timeout             */
#define SMB2_SERVICE_SLEEP  100     /* us — yield when nothing to poll          */

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
 * smb2_pending_t  —  entry in the submit queue
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
} smb2_op_t;

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

/* forward declarations */
static smb2_svc_t *g_svc = NULL;

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
 * Dispatch — called only from service thread
 * ========================================================================= */

static int dispatch(smb2_svc_t *svc, smb2_pending_t *p) {
    smb2_cb_ctx_t *ctx = malloc(sizeof(*ctx));
    if (!ctx) return -1;
    ctx->svc    = svc;
    ctx->result = p->result;

    int rc = 0;
    switch (p->op) {
        case SMB2_OP_CONNECT:
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
            break;
        case SMB2_OP_OPEN:
            rc = smb2_open_async(svc->smb2,
                     p->args.open.path,
                     p->args.open.flags,
                     generic_cb, ctx);
            break;
        case SMB2_OP_CLOSE:
            rc = smb2_close_async(svc->smb2,
                     p->args.close.fh,
                     generic_cb, ctx);
            break;
        case SMB2_OP_READ:
            rc = smb2_read_async(svc->smb2,
                     p->args.read.fh,
                     p->args.read.buf,
                     p->args.read.len,
                     generic_cb, ctx);
            break;
        case SMB2_OP_WRITE:
            rc = smb2_write_async(svc->smb2,
                     p->args.write.fh,
                     p->args.write.buf,
                     p->args.write.len,
                     generic_cb, ctx);
            break;
        case SMB2_OP_STAT:
            rc = smb2_stat_async(svc->smb2,
                     p->args.stat.path,
                     p->args.stat.st,      /* caller-allocated, filled in-place */
                     generic_cb, ctx);
            break;
        case SMB2_OP_MKDIR:
            rc = smb2_mkdir_async(svc->smb2,
                     p->args.mkdir.path,
                     generic_cb, ctx);
            break;
        case SMB2_OP_UNLINK:
            rc = smb2_unlink_async(svc->smb2,
                     p->args.unlink.path,
                     generic_cb, ctx);
            break;
        case SMB2_OP_RENAME:
            rc = smb2_rename_async(svc->smb2,
                     p->args.rename.oldpath,
                     p->args.rename.newpath,
                     generic_cb, ctx);
            break;
        default:
            rc = -1;
            break;
    }

    if (rc < 0) {
        free(ctx);
        return -1;
    }

    svc->inflight++;
    return 0;
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
                /* dispatch failed — complete with error immediately */
                pthread_mutex_lock(&p->result->lock);
                p->result->status = -1;
                p->result->done   = 1;
                pthread_cond_signal(&p->result->cond);
                pthread_mutex_unlock(&p->result->lock);
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
 * Demo — multiple producer threads issuing concurrent reads
 * ========================================================================= */

#define NUM_PRODUCERS   400
#define READS_PER_PROD  80
#define READ_BUF_SIZE   65536

typedef struct {
    smb2_svc_t  *svc;
    int          id;
    const char  *path;
} producer_args_t;

static void *producer_thread(void *arg) {
    producer_args_t *a   = arg;
    smb2_svc_t      *svc = a->svc;

    struct smb2fh *fh = NULL;
    int rc = smb2_blocking_open(svc, a->path, O_RDONLY, &fh);
    if (rc < 0 || !fh) {
        fprintf(stderr, "[prod %d] open failed: %d\n", a->id, rc);
        return NULL;
    }
    fprintf(stderr, "[prod %d] opened %s\n", a->id, a->path);

    uint8_t *buf = malloc(READ_BUF_SIZE);

    for (int i = 0; i < READS_PER_PROD; i++) {
        int n = smb2_blocking_read(svc, fh, buf, READ_BUF_SIZE);
        if (n < 0) {
            fprintf(stderr, "[prod %d] read %d failed: %d\n", a->id, i, n);
            break;
        }
        fprintf(stderr, "[prod %d] read %d: got %d bytes\n", a->id, i, n);
        if (n == 0) break;   /* EOF */
    }

    free(buf);
    smb2_blocking_close(svc, fh);
    fprintf(stderr, "[prod %d] done\n", a->id);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <server> <share> <path> [user] [password]\n",
                argv[0]);
        return 1;
    }

    const char *server   = argv[1];
    const char *share    = argv[2];
    const char *path     = argv[3];
    const char *user     = (argc >= 5) ? argv[4] : NULL;
    const char *password = (argc >= 6) ? argv[5] : NULL;

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

    /* launch producer threads — all share the same svc / TCP connection */
    pthread_t        threads[NUM_PRODUCERS];
    producer_args_t  args[NUM_PRODUCERS];

    for (int i = 0; i < NUM_PRODUCERS; i++) {
        args[i].svc  = svc;
        args[i].id   = i;
        args[i].path = path;
        pthread_create(&threads[i], NULL, producer_thread, &args[i]);
    }

    for (int i = 0; i < NUM_PRODUCERS; i++)
        pthread_join(threads[i], NULL);

    smb2_svc_shutdown(svc);
    fprintf(stderr, "shutdown complete\n");
    return 0;
}
