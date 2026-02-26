/*
* Copyright 2026 Rochus Keller <mailto:me@rochus-keller.ch>
*
* The following is the license that applies to this copy of the
* file. For a license to use the file under conditions
* other than those described here, please email to me@rochus-keller.ch.
*
* GNU General Public License Usage
* This file may be used under the terms of the GNU General Public
* License (GPL) versions 2.0 or 3.0 as published by the Free Software
* Foundation and appearing in the file LICENSE.GPL included in
* the packaging of this file. Please review the following information
* to ensure GNU General Public Licensing requirements will be met:
* http://www.fsf.org/licensing/licenses/info/GPLv2.html and
* http://www.gnu.org/copyleft/gpl.html.
*/

/*
 * main.c — command-line driver for the OP2 Oberon compiler
 *
 * Options are translated into the compact options string that
 * OP2$ParseOptions expects (see OP2.Mod / OP2.c for details).
 *
 * Default code-generation flags (already ON unless toggled):
 *   inxchk  (x) – array index bounds check
 *   typchk  (t) – type guard / type test check
 *   ptrinit (p) – initialise pointers to NIL
 *   assert  (a) – evaluate ASSERT statements
 *   fullstackinit (z) – zero-initialise entire stack frame
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gc.h>
#include "OP2.h"   /* defines MIC$AP, OP2$CompileFile, OP2$init$, GC_INIT */

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/* Maximum lengths imposed by OPM's fixed buffers (see OP2$Module).   */
#define MAX_PATH_LEN   31   /* OPM$outputPath  is 32 bytes            */
#define MAX_PREFIX_LEN 31   /* OPM$outputPrefix is 32 bytes           */
#define MAX_EXT_LEN     7   /* OPM$extension   is  8 bytes            */

static void print_help(const char *prog)
{
    printf("Usage: %s [options] <file.Mod> [<file.Mod> ...]\n\n", prog);

    printf("Output control:\n");
    printf("  -o, --output <path>    Output directory (trailing '/' required).\n");
    printf("                         Maps to ParseOptions 'P' token.\n");
    printf("                         Max %d characters.\n", MAX_PATH_LEN);
    printf("  -O, --prefix <pfx>     Output file-name prefix.\n");
    printf("                         Maps to ParseOptions 'O' token.\n");
    printf("                         Mutually exclusive with --use-mod-prefix.\n");
    printf("      --ext <ext>        Output file extension incl. dot (default: .Obj).\n");
    printf("                         Maps to ParseOptions '.' token. Max %d chars.\n", MAX_EXT_LEN);
    printf("  -X, --use-mod-prefix   Use the module-name qualifier as the output prefix.\n");
    printf("                         Mutually exclusive with --prefix.\n\n");

    printf("Code-generation flags  (starred = ON by default; flag toggles the bit):\n");
    printf("  --no-index-check  *    Disable array index bounds checking.\n");
    printf("  --no-type-check   *    Disable type guard / type test checking.\n");
    printf("  --no-ptr-init     *    Disable automatic NIL-initialisation of pointers.\n");
    printf("  --no-assert       *    Disable evaluation of ASSERT statements.\n");
    printf("  --no-stack-init   *    Disable full stack-frame zero-initialisation.\n");
    printf("  --overflow-check       Enable integer overflow checking.\n");
    printf("  --trace                Enable OPM trace mode (q).\n");
    printf("  --trace-procs          Enable procedure-call tracing (T).\n\n");

    printf("Symbol-file control:\n");
    printf("  -s, --new-symfile      Allow creation of a new symbol file.\n");
    printf("  -e, --ext-symfile      Allow creation of an extended symbol file.\n\n");

    printf("Parser / compiler flags:\n");
    printf("  --no-sys-check         Disable rejection of modules importing SYSTEM.\n");
    printf("  --dry-run              Parse only; do not write any output files.\n");
    printf("  --find-pc              Find source position for a given break PC.\n");
    printf("  --warnings             Display compiler warnings.\n");
    printf("  --oberon2              Compile in Oberon-2 mode.\n");
    printf("  --oberon1              Compile in Oberon-1 mode.\n\n");

    printf("Miscellaneous:\n");
    printf("  --raw-opts <str>       Append a raw ParseOptions string verbatim.\n");
    printf("                         Use for options not yet exposed as flags.\n");
    printf("  -h, --help             Show this help and exit.\n\n");

    printf("Note: flags that are ON by default (marked *) are toggled when specified,\n");
    printf("i.e. passing --no-index-check once turns it OFF; passing it twice turns\n");
    printf("it back ON.\n");
}

/* ------------------------------------------------------------------ */
/*  opts-string builder                                                */
/* ------------------------------------------------------------------ */

/*
 * We build a compact option string for ParseOptions.
 *
 * Layout: <single-char flags> [P<path><SP>] [O<prefix><SP>] [.<ext><SP>]
 *
 * Single-char flags have no delimiters between them.
 * Compound tokens (P, O, .) must be terminated by a space OR the string's
 * NUL — but because the inner loop in ParseOptions consumes that NUL, we
 * always append an explicit space so the outer loop can re-enter safely.
 * The buffer is zero-initialised, providing a second guard.
 */
#define OPTS_BUF 512

static int opts_append_str(char *buf, int pos, const char *s)
{
    while (*s)
        buf[pos++] = *s++;
    return pos;
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    GC_INIT();
    OP2$init$();

    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    /* Zero-initialised: guards against ParseOptions reading past NUL. */
    char opts[OPTS_BUF] = {0};
    int  opos = 0;                  /* write cursor into opts[]        */

    char output_path[MAX_PATH_LEN + 1]   = {0};
    char output_prefix[MAX_PREFIX_LEN + 1] = {0};
    char output_ext[MAX_EXT_LEN + 1]     = {0};

    /* Collect input file paths in a second array.                     */
    const char **files = (const char **)malloc((size_t)argc * sizeof(char *));
    if (!files) { fputs("Out of memory\n", stderr); return 1; }
    int file_count = 0;

#define ADDOPT(c)  do { opts[opos++] = (char)(c); } while (0)

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        /* ---- help ------------------------------------------------- */
        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            print_help(argv[0]);
            free(files);
            return 0;
        }

        /* ---- output path ------------------------------------------ */
        else if (!strcmp(arg, "-o") || !strcmp(arg, "--output")) {
            if (++i >= argc) {
                fprintf(stderr, "error: %s requires an argument\n", arg);
                free(files); return 1;
            }
            strncpy(output_path, argv[i], MAX_PATH_LEN);
        }
        else if (!strncmp(arg, "--output=", 9)) {
            strncpy(output_path, arg + 9, MAX_PATH_LEN);
        }

        /* ---- output prefix ---------------------------------------- */
        else if (!strcmp(arg, "-O") || !strcmp(arg, "--prefix")) {
            if (++i >= argc) {
                fprintf(stderr, "error: %s requires an argument\n", arg);
                free(files); return 1;
            }
            strncpy(output_prefix, argv[i], MAX_PREFIX_LEN);
        }

        /* ---- file extension --------------------------------------- */
        else if (!strcmp(arg, "--ext")) {
            if (++i >= argc) {
                fprintf(stderr, "error: --ext requires an argument\n");
                free(files); return 1;
            }
            /* Accept with or without leading dot. */
            const char *ext = argv[i];
            if (ext[0] != '.') {
                output_ext[0] = '.';
                strncpy(output_ext + 1, ext, MAX_EXT_LEN - 1);
            } else {
                strncpy(output_ext, ext, MAX_EXT_LEN);
            }
        }

        /* ---- use-mod-prefix --------------------------------------- */
        else if (!strcmp(arg, "-X") || !strcmp(arg, "--use-mod-prefix")) {
            ADDOPT('X');
        }

        /* ---- code-generation flags (toggle) ----------------------- */
        else if (!strcmp(arg, "--no-index-check"))  ADDOPT('x');
        else if (!strcmp(arg, "--no-type-check"))   ADDOPT('t');
        else if (!strcmp(arg, "--no-ptr-init"))     ADDOPT('p');
        else if (!strcmp(arg, "--no-assert"))       ADDOPT('a');
        else if (!strcmp(arg, "--no-stack-init"))   ADDOPT('z');
        else if (!strcmp(arg, "--overflow-check"))  ADDOPT('v');
        else if (!strcmp(arg, "--trace"))           ADDOPT('q');
        else if (!strcmp(arg, "--trace-procs"))     ADDOPT('T');

        /* ---- symbol-file flags ------------------------------------ */
        else if (!strcmp(arg, "-s") || !strcmp(arg, "--new-symfile"))  ADDOPT('s');
        else if (!strcmp(arg, "-e") || !strcmp(arg, "--ext-symfile"))  ADDOPT('e');

        /* ---- parser flags ---------------------------------------- */
        else if (!strcmp(arg, "--no-sys-check"))  ADDOPT('S');
        else if (!strcmp(arg, "--dry-run"))       ADDOPT('n');
        else if (!strcmp(arg, "--find-pc"))       ADDOPT('f');
        else if (!strcmp(arg, "--warnings"))      ADDOPT('w');
        else if (!strcmp(arg, "--oberon2"))       ADDOPT('2');
        else if (!strcmp(arg, "--oberon1"))       ADDOPT('1');

        /* ---- raw pass-through ------------------------------------- */
        else if (!strcmp(arg, "--raw-opts")) {
            if (++i >= argc) {
                fputs("error: --raw-opts requires an argument\n", stderr);
                free(files); return 1;
            }
            opos = opts_append_str(opts, opos, argv[i]);
        }

        /* ---- unknown option --------------------------------------- */
        else if (arg[0] == '-') {
            fprintf(stderr, "error: unknown option '%s' (try --help)\n", arg);
            free(files); return 1;
        }

        /* ---- input file ------------------------------------------ */
        else {
            files[file_count++] = arg;
        }
    }

    /* Append compound options at the end.
     * Each is followed by a space so that ParseOptions' inner scan loop
     * terminates cleanly and the outer loop can continue.              */
    if (output_path[0]) {
        size_t len = strlen(output_path);
        if (len > MAX_PATH_LEN) {
            fprintf(stderr, "error: output path too long (max %d chars)\n",
                    MAX_PATH_LEN);
            free(files); return 1;
        }
        ADDOPT('P');
        opos = opts_append_str(opts, opos, output_path);
        ADDOPT(' ');
    }
    if (output_prefix[0]) {
        size_t len = strlen(output_prefix);
        if (len > MAX_PREFIX_LEN) {
            fprintf(stderr, "error: prefix too long (max %d chars)\n",
                    MAX_PREFIX_LEN);
            free(files); return 1;
        }
        ADDOPT('O');
        opos = opts_append_str(opts, opos, output_prefix);
        ADDOPT(' ');
    }
    if (output_ext[0]) {
        size_t len = strlen(output_ext);
        if (len > MAX_EXT_LEN) {
            fprintf(stderr, "error: extension too long (max %d chars incl. dot)\n",
                    MAX_EXT_LEN);
            free(files); return 1;
        }
        /* The '.' token handler in ParseOptions includes the dot in the
         * stored extension, so we pass it as-is (output_ext[0] == '.'). */
        opos = opts_append_str(opts, opos, output_ext);
        ADDOPT(' ');
    } else {
        opos = opts_append_str(opts, opos, ".Obj");
        ADDOPT(' ');
    }
    /* opts[opos] is already 0 (zero-init). */

    if (file_count == 0) {
        fputs("error: no input files specified\n\n", stderr);
        print_help(argv[0]);
        free(files); return 1;
    }

    /* ---- compile each file --------------------------------------- */
    int errors = 0;
    for (int i = 0; i < file_count; i++) {
        const char *path = files[i];
        unsigned char err = 0;
        OP2$CompileFile(
            (MIC$AP){ (uint32_t)(strlen(path) + 1), path },
            (MIC$AP){ (uint32_t)(opos + 1),         opts },
            &err
        );
        if (err) errors++;
    }

    free(files);
    return errors ? 1 : 0;
}

