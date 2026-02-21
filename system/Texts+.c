#include "Texts.h"
#include <gc.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/* Access raw pointer from MIC$AP (open array) */
static void *mic_addr(MIC$AP ap) { return ap.$; }

/* -------------------------------------------------------------------------- */
/* Writer Procedures                                                          */
/* -------------------------------------------------------------------------- */

/* PROCEDURE~ OpenWriter* (VAR W: Writer); */
void Texts$OpenWriter(Texts$Writer *W) {
    if (!W) return;
    W->buf = NULL; /* Reset buffer */
    W->pos = 0;
}

/* PROCEDURE~ Write* (VAR W: Writer; ch: CHAR); */
void Texts$Write(Texts$Writer *W, uint8_t ch) {
    if (ch == 13 || ch == '\r')
        ch = '\n';
    printf("%c", ch);
}

/* PROCEDURE~ WriteInt* (VAR W: Writer; x, n: LONGINT); */
void Texts$WriteInt(Texts$Writer *W, int x, int n) {
    char buf[32];
    int len, i;

    /* Format integer into temp buffer */
    len = sprintf(buf, "%d", x);

    /* Pad with spaces */
    for (i = 0; i < n - len; i++) {
        Texts$Write(W, ' ');
    }

    /* Write digits */
    for (i = 0; i < len; i++) {
        Texts$Write(W, buf[i]);
    }
}

/* PROCEDURE~ WriteHex* (VAR W: Writer; x: LONGINT); */
void Texts$WriteHex(Texts$Writer *W, int x) {
    char buf[32];
    int len, i;

    len = sprintf(buf, "%X", (unsigned int)x); // Upper case hex

    for (i = 0; i < len; i++) {
        Texts$Write(W, buf[i]);
    }
}

/* PROCEDURE~ Append* (T: Text; B: Buffer); */
void Texts$Append(Texts$Text T, Texts$Buffer B) {

    // this has no effect otherwise sinde we already printed everything before
    if (B && B->data && B->len > 0) {
        fwrite(B->data, 1, B->len, stdout);

        B->len = 0;
    }
    fflush(stdout);
}

/* -------------------------------------------------------------------------- */
/* Reader Procedures                                                          */
/* -------------------------------------------------------------------------- */

/* PROCEDURE~ OpenReader* (VAR R: Reader; name: ARRAY OF CHAR): BOOLEAN; */
/* Note: Your Mod signature returns BOOLEAN, C stub returns unsigned char */
unsigned char Texts$OpenReader(Texts$Reader *R, MIC$AP name) {
    const char *path = (const char *)mic_addr(name);
    FILE *fp;

    if (!R) return 0;

    /* Initialize default state */
    R->eot = 1;
    R->lib = GC_MALLOC(sizeof(struct Fonts$_$0)); /* make OPM.Get happy */
    Fonts$_$0$init$(R->lib, 1);
    R->fp = NULL;
    R->pos = 0;
    R->len = 0;

    if (!path || !*path) return 0; // False

    fp = fopen(path, "rb");
    if (!fp) return 0; // False

    R->fp = (void *)fp;

    /* Get length */
    fseek(fp, 0, SEEK_END);
    R->len = (int)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    R->eot = (R->len == 0);
    R->pos = 0;

    return 1; // True
}

/* PROCEDURE~ Read* (VAR R: Reader; VAR ch: CHAR); */
void Texts$Read(Texts$Reader *R, uint8_t *ch) {
    FILE *fp;
    int c;

    if (!ch) return;
    *ch = 0; /* Default to 0X on error/eot */

    if (!R || !R->fp || R->eot) {
        if (R) R->eot = 1;
        return;
    }

    fp = (FILE *)R->fp;

    /* Read one byte */
    fseek(fp, R->pos, SEEK_SET);
    c = fgetc(fp);

    if (c == EOF) {
        R->eot = 1;
        *ch = 0;
    } else {
        *ch = (char)c;
        R->pos++;
        /* Check if we just hit end */
        if (R->pos >= R->len) {
            R->eot = 1;
        }
    }
}

/* PROCEDURE~ Pos* (VAR R: Reader): LONGINT; */
int Texts$Pos(Texts$Reader *R) {
    if (!R) return 0;
    return R->pos;
}
