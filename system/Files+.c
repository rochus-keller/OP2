#include "Files.h"
#include <gc.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
// #include <unistd.h>

/* -------------------------------------------------------------------------- */
/* Internal File Structure                                                    */
/* -------------------------------------------------------------------------- */

/*
 * We extend the empty generated Files$_$0 struct.
 * This must match the pointer type 'Files$File' cast.
 */
typedef struct Files_Impl {
    struct Files$_$0$Class$* class$; /* Inherited base header */
    FILE *fp;                        /* C stdio stream */
    char *name;                      /* Registered name */
    char *tmppath;                   /* Disk path (temp for New) */
    int is_temp;                     /* 1 if New() used, 0 after Register() */
    struct Files_Impl *next;         /* Linked list for Old() lookup */
} Files_Impl;

/* Global list of open files to support Files.Old returning the same handle */
static Files_Impl *g_files_head = NULL;
static unsigned long g_tmp_seq = 0;

/* -------------------------------------------------------------------------- */
/* Helper Functions                                                           */
/* -------------------------------------------------------------------------- */

/* GC-safe string duplication */
static char *gc_strdup(const char *s) {
    size_t len;
    char *p;
    if (!s) return NULL;
    len = strlen(s) + 1;
    p = (char *)GC_MALLOC_ATOMIC(len);
    if (p) memcpy(p, s, len);
    return p;
}

static Files_Impl *files_from_handle(Files$File f) {
    return (Files_Impl *)f;
}

static Files$File handle_from_files(Files_Impl *fi) {
    return (Files$File)fi;
}

static void *mic_addr(MIC$AP ap) { return ap.$; }

static void printrealpath( const char* path)
{
#if 0
    char resolved[PATH_MAX];
    if (realpath(path, resolved) != NULL)
        printf("open file: %s\n", resolved);
#endif
}

/* -------------------------------------------------------------------------- */
/* Procedures                                                                 */
/* -------------------------------------------------------------------------- */

/* PROCEDURE~ Old*(name: ARRAY OF CHAR): File; */
Files$File Files$Old(MIC$AP name) {
    const char *path = (const char *)mic_addr(name);
    Files_Impl *curr = g_files_head;
    FILE *fp;
    Files_Impl *fi;

    if (!path || !*path) return NULL;

    /* 1. Check if already open */
    while (curr) {
        if (!curr->is_temp && curr->name && strcmp(curr->name, path) == 0) {
            return handle_from_files(curr);
        }
        curr = curr->next;
    }

    /* 2. Try to open existing file */
    printrealpath(path);
    fp = fopen(path, "rb+");
    if (!fp)
        fp = fopen(path, "rb"); /* Fallback to read-only */
    if (!fp)
        return NULL;

    /* 3. Allocate */
    fi = (Files_Impl *)GC_MALLOC(sizeof(Files_Impl));
    Files$_$0$init$((Files$_$0 *)fi, 1);     /* Run generated init */
    fi->class$ = &Files$_$0$class$;          /* Restore vtable if needed */

    fi->fp = fp;
    fi->name = gc_strdup(path);
    fi->tmppath = NULL;
    fi->is_temp = 0;

    /* Link into global list */
    fi->next = g_files_head;
    g_files_head = fi;

    return handle_from_files(fi);
}

/* PROCEDURE~ New*(name: ARRAY OF CHAR): File; */
Files$File Files$New(MIC$AP name) {
    const char *req_name = (const char *)mic_addr(name);
    Files_Impl *fi;
    FILE *fp;
    char tmp_name[128];

    if (!req_name)
        return NULL;

    /* Generate unique temp name */
    g_tmp_seq++;
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp.%lu", req_name, g_tmp_seq);

    printrealpath(tmp_name);
    fp = fopen(tmp_name, "wb+");
    if (!fp)
        return NULL;

    fi = (Files_Impl *)GC_MALLOC(sizeof(Files_Impl));
    Files$_$0$init$((Files$_$0 *)fi, 1);
    fi->class$ = &Files$_$0$class$;

    fi->fp = fp;
    fi->name = gc_strdup(req_name);
    fi->tmppath = gc_strdup(tmp_name);
    fi->is_temp = 1;

    /* Link into global list */
    fi->next = g_files_head;
    g_files_head = fi;

    return handle_from_files(fi);
}

/* PROCEDURE~ Close*(f: File); */
void Files$Close(Files$File f) {
    Files_Impl *fi = files_from_handle(f);
    Files_Impl **pp;

    if (!fi) return;

    /* Remove from global list so Old() doesn't find it anymore */
    pp = &g_files_head;
    while (*pp) {
        if (*pp == fi) {
            *pp = fi->next;
            break;
        }
        pp = &(*pp)->next;
    }

    if (fi->fp) {
        fflush(fi->fp);
        fclose(fi->fp);
        fi->fp = NULL;
    }
}

/* PROCEDURE~ Register*(f: File); */
void Files$Register(Files$File f) {
    Files_Impl *fi = files_from_handle(f);

    if (!fi || !fi->is_temp || !fi->fp)
        return;

    /* Close temp file so we can move it */
    fclose(fi->fp);
    fi->fp = NULL;

    /* Standard C rename (remove target first for portability) */
    remove(fi->name);
    if (rename(fi->tmppath, fi->name) == 0) {
        fi->is_temp = 0;
        /* Reopen the real file */
        fi->fp = fopen(fi->name, "rb+");
    } else {
        /* Failed: reopen temp to keep handle valid */
        fi->fp = fopen(fi->tmppath, "rb+");
    }
}

/* PROCEDURE~ Length*(f: File): LONGINT; */
int Files$Length(Files$File f) {
    Files_Impl *fi = files_from_handle(f);
    long pos, len;

    if (!fi || !fi->fp)
        return 0;

    pos = ftell(fi->fp);
    fseek(fi->fp, 0, SEEK_END);
    len = ftell(fi->fp);
    fseek(fi->fp, pos, SEEK_SET);

    return (int)len;
}

/* PROCEDURE~ Set*(VAR r: Rider; f: File; pos: LONGINT); */
void Files$Set(Files$Rider *r, Files$File f, int pos) {
    Files_Impl *fi = files_from_handle(f);
    int len;

    if (!r)
        return;

    r->file = f;
    r->res = 0;

    if (!fi || !fi->fp) {
        r->eof = 1;
        r->pos = 0;
        return;
    }

    len = Files$Length(f);
    if (pos > len) pos = len;
    if (pos < 0) pos = 0;

    r->pos = pos;
    r->eof = 0;
}

/* PROCEDURE~ Pos*(VAR r: Rider): LONGINT; */
int Files$Pos(Files$Rider *r) {
    return r ? r->pos : 0;
}

/* PROCEDURE~ Base*(VAR r: Rider): File; */
Files$File Files$Base(Files$Rider *r) {
    return r ? r->file : NULL;
}

/* PROCEDURE~ ReadBytes*(VAR r: Rider; VAR x: ARRAY OF SYSTEM.BYTE; n: LONGINT); */
void Files$ReadBytes(Files$Rider *r, MIC$AP x, int n) {
    Files_Impl *fi;
    size_t count;
    void *buf;

    if (!r || n <= 0)
        return;

    fi = files_from_handle(r->file);
    if (!fi || !fi->fp) {
        r->res = n;
        r->eof = 1;
        return;
    }

    /* Seek is mandatory because multiple Riders may share one FILE* */
    fseek(fi->fp, r->pos, SEEK_SET);

    buf = x.$;
    count = fread(buf, 1, n, fi->fp);

    r->pos += count;
    r->res = n - (int)count;

    if (r->res > 0) {
        r->eof = 1;
        /* Clear remaining buffer? Oberon usually leaves it undefined or untouched. */
        memset((char*)buf + count, 0, r->res);
    } else {
        r->eof = 0;
    }
}

/* PROCEDURE~ WriteBytes*(VAR r: Rider; VAR x: ARRAY OF SYSTEM.BYTE; n: LONGINT); */
void Files$WriteBytes(Files$Rider *r, MIC$AP x, int n) {
    Files_Impl *fi;
    size_t count;
    void *buf;

    if (!r || n <= 0)
        return;

    fi = files_from_handle(r->file);
    if (!fi || !fi->fp) {
        r->res = n;
        r->eof = 1;
        return;
    }

    fseek(fi->fp, r->pos, SEEK_SET);

    buf = mic_addr(x);
    count = fwrite(buf, 1, n, fi->fp);

    r->pos += count;
    r->res = n - (int)count;
    r->eof = 0; /* Write usually clears EOF unless disk full */
}

/* Wrapper helpers for single byte I/O */
void Files$Read(Files$Rider *r, unsigned char *x) {
    MIC$AP ap;
    ap.$ = x; ap.$1 = 1;
    Files$ReadBytes(r, ap, 1);
}

void Files$Write(Files$Rider *r, unsigned char x) {
    MIC$AP ap;
    ap.$ = &x; ap.$1 = 1;
    Files$WriteBytes(r, ap, 1);
}

/* PROCEDURE~ ReadNum*(VAR R: Rider; VAR x: LONGINT); */
/* Reads Oberon compressed integer format */
void Files$ReadNum(Files$Rider *r, int *x) {
    unsigned char b;
    int shift = 0;
    long val = 0;

    if (!r || !x)
        return;

    /*
     * Oberon Format: Little-endian 7-bit groups.
     * Bytes 0..N-1 have MSB (0x80) set.
     * Byte N has MSB clear.
     * Sign bit is bit 6 of the last byte.
     */

    do {
        if (shift >= 32) { /* Safety break for malformed data */
            *x = 0;
            return;
        }
        Files$Read(r, &b);
        if (r->eof) {
            *x = 0;
            return;
        }

        val |= ((long)(b & 0x7F)) << shift;
        shift += 7;
    } while (b & 0x80);

    /* Sign extension handling */
    /* If the last group (b) has bit 6 set (0x40), the number is negative. */
    /* We must sign-extend from the current shift position up to 32 bits. */
    if ((b & 0x40) && shift < 32) {
        val |= ((long)-1) << shift;
    }

    *x = (int)val;
}
