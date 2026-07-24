/*
 * PE-Any - A simple Win32 GUI tool inspired by Detect It Easy (DIE)
 * Developer: zrnge.com
 * GitHub:   github.com/zrnge/pe-any
 * Features:
 *   - General file info (size, entropy, SHA-256)
 *   - PE info (headers, sections, subsystem, entry point)
 *   - Import table parsing
 *   - Export table parsing
 *   - ASCII/Unicode string extraction
 *   - Hex dump
 *
 * Compile with MinGW/GCC:
 *   gcc -O2 -o pe-any.exe pe-any.c -mwindows -lcomctl32 -lcomdlg32
 * Compile with MSVC:
 *   cl /W3 /O2 pe-any.c /Fepe-any.exe user32.lib gdi32.lib comctl32.lib comdlg32.lib
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <math.h>
#include <stdarg.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

/* PE definitions are provided by windows.h, but keep a few helpers */
#ifndef IMAGE_NUMBEROF_DIRECTORY_ENTRIES
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#endif

/* SHA-256 context */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    uint32_t datalen;
} sha256_ctx;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
    int i,j;
    for (i=0,j=0; i<16; ++i, j+=4)
        m[i] = ((uint32_t)data[j]<<24) | ((uint32_t)data[j+1]<<16) | ((uint32_t)data[j+2]<<8) | (uint32_t)data[j+3];
    for (; i<64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i=0; i<64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    /* Fill any partial block already in the buffer */
    if (ctx->datalen > 0) {
        size_t fill = 64 - ctx->datalen;
        if (fill > len) fill = len;
        memcpy(ctx->data + ctx->datalen, data, fill);
        ctx->datalen += (uint32_t)fill;
        i += fill;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
    /* Process full 64-byte blocks directly — no per-byte copy */
    while (i + 64 <= len) {
        sha256_transform(ctx, data + i);
        ctx->bitlen += 512;
        i += 64;
    }
    /* Store remaining bytes (0–63) */
    if (i < len) {
        size_t rem = len - i;
        memcpy(ctx->data, data + i, rem);
        ctx->datalen = (uint32_t)rem;
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    /* SHA-256 requires big-endian 64-bit length at bytes 56-63 */
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    sha256_transform(ctx, ctx->data);
    for (i=0; i<4; ++i) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24-i*8)) & 0xff);
        hash[i+4]    = (uint8_t)((ctx->state[1] >> (24-i*8)) & 0xff);
        hash[i+8]    = (uint8_t)((ctx->state[2] >> (24-i*8)) & 0xff);
        hash[i+12]   = (uint8_t)((ctx->state[3] >> (24-i*8)) & 0xff);
        hash[i+16]   = (uint8_t)((ctx->state[4] >> (24-i*8)) & 0xff);
        hash[i+20]   = (uint8_t)((ctx->state[5] >> (24-i*8)) & 0xff);
        hash[i+24]   = (uint8_t)((ctx->state[6] >> (24-i*8)) & 0xff);
        hash[i+28]   = (uint8_t)((ctx->state[7] >> (24-i*8)) & 0xff);
    }
}

static double calc_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i=0; i<len; ++i) freq[data[i]]++;
    double ent = 0.0;
    for (int i=0; i<256; ++i) {
        if (freq[i]) {
            double p = (double)freq[i] / (double)len;
            ent -= p * log2(p);
        }
    }
    return ent;
}

static uint8_t *read_file(const char *path, size_t *out_size) {
    *out_size = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    __int64 sz_i64 = _ftelli64(f);
    if (sz_i64 < 0) { fclose(f); return NULL; }
    size_t sz = (size_t)sz_i64;
    if (_fseeki64(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    uint8_t *buf = NULL;
    if (sz > 0) {
        buf = (uint8_t *)malloc(sz);
        if (!buf) { fclose(f); return NULL; }
        if (fread(buf, 1, sz, f) != sz) {
            free(buf); fclose(f); return NULL;
        }
    }
    fclose(f);
    *out_size = sz;
    return buf;
}

static int is_pe(const uint8_t *buf, size_t size) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return 0;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)buf;
    if (dos->e_magic != 0x5A4D) return 0; /* "MZ" */
    if ((DWORD)dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || (DWORD)dos->e_lfanew > size ||
        size - (DWORD)dos->e_lfanew < 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD))
        return 0;
    DWORD pe_sig = *(const DWORD *)(buf + dos->e_lfanew);
    if (pe_sig != IMAGE_NT_SIGNATURE) return 0;
    return 1;
}

static const char *machine_name(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86 (I386)";
        case IMAGE_FILE_MACHINE_AMD64: return "x64 (AMD64)";
        case IMAGE_FILE_MACHINE_ARM:   return "ARM";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default: return "Unknown";
    }
}

static const char *subsystem_name(WORD sub) {
    switch (sub) {
        case IMAGE_SUBSYSTEM_UNKNOWN:                  return "Unknown";
        case IMAGE_SUBSYSTEM_NATIVE:                   return "Native (driver)";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:              return "Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:              return "Windows CUI";
        case IMAGE_SUBSYSTEM_OS2_CUI:                  return "OS/2 CUI";
        case IMAGE_SUBSYSTEM_POSIX_CUI:                return "POSIX CUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:           return "Windows CE GUI";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:          return "EFI Application";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:  return "EFI Driver (with boot)";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:       return "EFI Driver (runtime)";
        case IMAGE_SUBSYSTEM_EFI_ROM:                  return "EFI ROM Image";
        case IMAGE_SUBSYSTEM_XBOX:                     return "XBOX";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "Windows Boot Application";
        default: return "Unknown";
    }
}

static const char *dir_name(int idx) {
    static const char *names[] = {
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
        "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
        "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"
    };
    if (idx >= 0 && idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return names[idx];
    return "?";
}

/* Returns offset on success, or SIZE_MAX on failure. This distinguishes offset 0 from "not found". */
static size_t rva_to_offset(DWORD rva, const IMAGE_SECTION_HEADER *sections, WORD num_sections) {
    for (WORD i = 0; i < num_sections; ++i) {
        DWORD va = sections[i].VirtualAddress;
        DWORD sz = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        if (rva >= va && sz > 0 && (rva - va) < sz) {
            DWORD delta = rva - va;
            DWORD raw = sections[i].PointerToRawData;
            if ((size_t)raw + (size_t)delta < (size_t)raw) return SIZE_MAX; /* overflow */
            return (size_t)raw + (size_t)delta;
        }
    }
    return SIZE_MAX;
}

/* String builder for efficient edit-control output */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} str_builder;

static void sb_init(str_builder *sb) {
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
}

static void sb_free(str_builder *sb) {
    free(sb->buf);
    sb->buf = NULL;
    sb->len = sb->cap = 0;
}

static int sb_ensure(str_builder *sb, size_t extra) {
    size_t need = sb->len + extra + 1;
    if (need <= sb->cap) return 1;
    size_t newcap = sb->cap ? sb->cap * 2 : 4096;
    while (newcap < need) {
        if (newcap > SIZE_MAX / 2) { newcap = SIZE_MAX; break; }
        newcap *= 2;
    }
    if (newcap < need) newcap = need;
    char *nb = (char *)realloc(sb->buf, newcap);
    if (!nb) return 0;
    sb->buf = nb;
    sb->cap = newcap;
    return 1;
}

static void sb_printf(str_builder *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
#ifdef _MSC_VER
    /* MSVC vsnprintf returns -1 on overflow instead of the required size */
    int n = _vscprintf(fmt, ap);
#else
    int n = vsnprintf(NULL, 0, fmt, ap);
#endif
    va_end(ap);
    if (n < 0) return;
    if (!sb_ensure(sb, (size_t)n)) return;
    va_start(ap, fmt);
    vsnprintf(sb->buf + sb->len, sb->cap - sb->len, fmt, ap);
    va_end(ap);
    sb->len += (size_t)n;
}

static void sb_append_cstr(str_builder *sb, const char *s) {
    size_t n = strlen(s);
    if (!sb_ensure(sb, n)) return;
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
}

/* GUI globals */
static HWND g_hMain = NULL;
static HWND g_hTab = NULL;
static HWND g_hPath = NULL;
static HWND g_hBrowse = NULL;
static HWND g_hEditGeneral = NULL;
static HWND g_hEditPE = NULL;
static HWND g_hEditImports = NULL;
static HWND g_hEditExports = NULL;
static HWND g_hEditStrings = NULL;
static HWND g_hEditHex = NULL;
static HWND g_hEditMinLen = NULL;
static HWND g_hBtnAscii = NULL;
static HWND g_hBtnUnicode = NULL;
static HWND g_hEditHexOffset = NULL;
static HWND g_hEditHexLen = NULL;
static HWND g_hBtnHexDump = NULL;
static HWND g_hStatus = NULL;
static HWND g_hLblMinLen = NULL;
static HWND g_hLblHexOffset = NULL;
static HWND g_hLblHexLen = NULL;
static HWND g_hEditStrFilter = NULL;
static HWND g_hLblStrFilter = NULL;
static HWND g_hEditPatterns = NULL;
static HWND g_hBtnScanPatterns = NULL;
static HWND g_hChkPatterns[9] = {NULL};

static uint8_t *g_buf = NULL;
static size_t g_size = 0;
static char g_path[MAX_PATH] = {0};

/* Cached PE headers — parsed once per file load, reused by PE Info / Imports / Exports tabs */
static struct {
    int valid;
    int is_pe;
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_FILE_HEADER *file;
    const IMAGE_OPTIONAL_HEADER32 *opt32;
    const IMAGE_OPTIONAL_HEADER64 *opt64;
    const IMAGE_SECTION_HEADER *sections;
    WORD num_sections;
    int is64;
} g_pe_cache;

/* Forward declaration — get_pe_headers is defined later in the file */
static int get_pe_headers(const uint8_t *buf, size_t size,
                          const IMAGE_DOS_HEADER **out_dos,
                          const IMAGE_FILE_HEADER **out_file,
                          const IMAGE_OPTIONAL_HEADER32 **out_opt32,
                          const IMAGE_OPTIONAL_HEADER64 **out_opt64,
                          const IMAGE_SECTION_HEADER **out_sections,
                          WORD *out_num_sections,
                          int *out_is64);

static void invalidate_pe_cache(void) {
    memset(&g_pe_cache, 0, sizeof(g_pe_cache));
}

static int ensure_pe_cache(void) {
    if (g_pe_cache.valid) return g_pe_cache.is_pe;
    g_pe_cache.valid = 1;
    if (!g_buf || !is_pe(g_buf, g_size)) {
        g_pe_cache.is_pe = 0;
        return 0;
    }
    g_pe_cache.is_pe = 1;
    return get_pe_headers(g_buf, g_size,
        &g_pe_cache.dos, &g_pe_cache.file,
        &g_pe_cache.opt32, &g_pe_cache.opt64,
        &g_pe_cache.sections, &g_pe_cache.num_sections,
        &g_pe_cache.is64);
}

#define IDC_BROWSE      1001
#define IDC_TAB         1002
#define IDC_EDIT_GENERAL 1010
#define IDC_EDIT_PE     1011
#define IDC_EDIT_IMPORTS 1012
#define IDC_EDIT_EXPORTS 1013
#define IDC_EDIT_STRINGS 1014
#define IDC_EDIT_HEX    1015
#define IDC_EDIT_MINLEN 1020
#define IDC_BTN_ASCII   1030
#define IDC_BTN_UNICODE 1031
#define IDC_EDIT_STRFILTER 1032
#define IDC_EDIT_HEXOFF 1040
#define IDC_EDIT_HEXLEN 1041
#define IDC_BTN_HEXDUMP 1042
#define IDC_EDIT_PATTERNS 1050
#define IDC_BTN_SCAN_PATTERNS 1051
#define IDC_CHK_PATTERN_BASE 1060

#define TAB_COUNT 7
#define DEFAULT_MIN_STRING_LEN 4
#define DEFAULT_HEX_LEN 256
#define MAX_HEX_DUMP_BYTES (1024 * 1024)
#define MAX_OUTPUT_LINES  50000   /* cap output to prevent memory exhaustion on huge files */

static void set_edit_text(HWND hEdit, const char *text) {
    SetWindowTextA(hEdit, text ? text : "");
}

static void set_status(const char *fmt, ...) {
    if (!g_hStatus) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    SetWindowTextA(g_hStatus, buf);
}

static void append_sanitized(str_builder *sb, const char *s, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        if (c == '\r') sb_append_cstr(sb, "\\r");
        else if (c == '\n') sb_append_cstr(sb, "\\n");
        else if (c == '\t') sb_append_cstr(sb, "\\t");
        else if ((unsigned char)c >= 32 && (unsigned char)c < 127) sb_printf(sb, "%c", c);
        else sb_printf(sb, "\\x%02X", (unsigned char)c);
    }
}

static void extract_strings(str_builder *sb, int min_len, int unicode, const char *filter) {
    if (!g_buf) {
        sb_printf(sb, "No file loaded.\r\n");
        return;
    }
    if (min_len < 1) min_len = 1;
    size_t count = 0;
    size_t line_count = 0;
    int filter_len = filter ? (int)strlen(filter) : 0;

    if (!unicode) {
        size_t i = 0;
        while (i < g_size) {
            size_t j = i;
            while (j < g_size && ((g_buf[j] >= 32 && g_buf[j] < 127) || g_buf[j] == '\t')) j++;
            size_t run = j - i;
            if ((int)run >= min_len) {
                int matched = (filter_len == 0);
                if (!matched) {
                    /* Fast first-char skip: only memcmp when first byte matches */
                    char fc = filter[0];
                    for (size_t k = i; k + filter_len <= i + run; ++k) {
                        if (g_buf[k] == (uint8_t)fc && memcmp(g_buf + k, filter, filter_len) == 0) {
                            matched = 1;
                            break;
                        }
                    }
                }
                if (matched) {
                    if (line_count < MAX_OUTPUT_LINES) {
                        sb_printf(sb, "0x%08zX: ", i);
                        append_sanitized(sb, (const char *)(g_buf + i), run);
                        sb_printf(sb, "\r\n");
                        line_count++;
                    }
                    count++;
                }
            }
            i = (run > 0) ? j + 1 : i + 1;
        }
    } else {
        size_t i = 0;
        while (i + 1 < g_size) {
            size_t j = i;
            while (j + 1 < g_size && g_buf[j] >= 32 && g_buf[j] < 127 && g_buf[j+1] == 0) j += 2;
            size_t run = (j - i) / 2;
            if ((int)run >= min_len) {
                int matched = (filter_len == 0);
                if (!matched) {
                    /* Unicode: compare filter chars against every-other byte */
                    for (size_t k = i; k < j; k += 2) {
                        size_t remain = (j - k) / 2;
                        if ((int)remain < filter_len) break;
                        int ok = 1;
                        for (int fi = 0; fi < filter_len; ++fi) {
                            if (g_buf[k + fi * 2] != (uint8_t)filter[fi]) { ok = 0; break; }
                        }
                        if (ok) { matched = 1; break; }
                    }
                }
                if (matched) {
                    if (line_count < MAX_OUTPUT_LINES) {
                        sb_printf(sb, "0x%08zX: ", i);
                        for (size_t k = i; k < j; k += 2) {
                            char c = (char)g_buf[k];
                            if (c == '\r') sb_append_cstr(sb, "\\r");
                            else if (c == '\n') sb_append_cstr(sb, "\\n");
                            else if (c == '\t') sb_append_cstr(sb, "\\t");
                            else if ((unsigned char)c >= 32 && (unsigned char)c < 127) sb_printf(sb, "%c", c);
                            else sb_printf(sb, "\\x%02X", (unsigned char)c);
                        }
                        sb_printf(sb, "\r\n");
                        line_count++;
                    }
                    count++;
                }
            }
            i = (run > 0) ? j + 2 : i + 2;
        }
    }
    if (line_count >= MAX_OUTPUT_LINES)
        sb_printf(sb, "\r\n(Output truncated at %d lines — %zu total matches found)\r\n", MAX_OUTPUT_LINES, count);
    sb_printf(sb, "\r\nTotal %s strings: %zu\r\n", unicode ? "Unicode" : "ASCII", count);
}

/* ---- Pattern matching (regex-like) for common data types ---- */

/* Simple case-insensitive substring search */
static int contains_nocase(const char *haystack, size_t haylen, const char *needle, size_t needlen) {
    if (needlen == 0) return 1;
    if (needlen > haylen) return 0;
    for (size_t i = 0; i <= haylen - needlen; ++i) {
        int match = 1;
        for (size_t j = 0; j < needlen; ++j) {
            char a = haystack[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

/* Check if a character is a valid domain label char (alnum or hyphen) */
static int is_domain_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-';
}

/* Check if a character is a valid TLD char (alpha only) */
static int is_tld_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* ---- Individual pattern matchers ---- */

/* IPv4: n.n.n.n where each n is 0-255, no leading zeros except "0" itself */
static int match_ipv4(const char *s, size_t len, size_t *out_len) {
    int dots = 0;
    size_t i = 0;
    for (int octet = 0; octet < 4; ++octet) {
        if (i >= len) return 0;
        /* Leading zero check */
        if (s[i] == '0' && i + 1 < len && s[i+1] >= '0' && s[i+1] <= '9') return 0;
        int val = 0;
        int digits = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9') {
            val = val * 10 + (s[i] - '0');
            if (val > 255) return 0;
            ++i;
            ++digits;
        }
        if (digits == 0) return 0;
        if (octet < 3) {
            if (i >= len || s[i] != '.') return 0;
            ++i;
            ++dots;
        }
    }
    *out_len = i;
    return 1;
}

/* IPv6: simplified — matches hex colon groups, compressed zeros, and optional IPv4 tail */
static int match_ipv6(const char *s, size_t len, size_t *out_len) {
    size_t i = 0;
    int groups = 0;
    int has_double_colon = 0;
    int has_ipv4_tail = 0;

    /* Check for leading :: */
    if (i + 1 < len && s[i] == ':' && s[i+1] == ':') {
        has_double_colon = 1;
        i += 2;
    }

    while (i < len && groups < 8) {
        /* Check for IPv4 tail */
        size_t ipv4_len = 0;
        if (match_ipv4(s + i, len - i, &ipv4_len)) {
            has_ipv4_tail = 1;
            i += ipv4_len;
            break;
        }

        /* Hex group */
        int hex_digits = 0;
        while (i < len && ((s[i] >= '0' && s[i] <= '9') ||
                           (s[i] >= 'a' && s[i] <= 'f') ||
                           (s[i] >= 'A' && s[i] <= 'F'))) {
            ++i;
            ++hex_digits;
        }
        if (hex_digits == 0) break;
        if (hex_digits > 4) return 0;
        groups++;

        /* Colon separator */
        if (i + 1 < len && s[i] == ':' && s[i+1] == ':') {
            if (has_double_colon) return 0; /* only one :: allowed */
            has_double_colon = 1;
            i += 2;
        } else if (i < len && s[i] == ':') {
            ++i;
        } else {
            break;
        }
    }

    if (groups == 0 && !has_double_colon) return 0;
    /* Reject trailing hex digits or colons after a full address */
    if (i < len && ((s[i] >= '0' && s[i] <= '9') ||
                    (s[i] >= 'a' && s[i] <= 'f') ||
                    (s[i] >= 'A' && s[i] <= 'F') || s[i] == ':'))
        return 0;
    if (has_ipv4_tail) {
        if (has_double_colon) { if (groups > 5) return 0; }
        else { if (groups != 6) return 0; }
    } else {
        if (has_double_colon) { if (groups > 7) return 0; }
        else { if (groups != 8) return 0; }
    }
    *out_len = i;
    return 1;
}

/* Email: local@domain.tld */
static int match_email(const char *s, size_t len, size_t *out_len) {
    size_t at_pos = 0;
    int found_at = 0;
    for (size_t i = 0; i < len; ++i) {
        if (s[i] == '@') { at_pos = i; found_at = 1; break; }
    }
    if (!found_at || at_pos == 0 || at_pos >= len - 3) return 0;

    /* Local part: alnum + ._-+% */
    for (size_t i = 0; i < at_pos; ++i) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '+' || c == '%'))
            return 0;
    }

    /* Domain part: must have at least one dot and end with alpha TLD */
    size_t dom_start = at_pos + 1;
    size_t dom_len = 0;
    int has_dot = 0;
    size_t last_dot = 0;
    for (size_t i = dom_start; i < len; ++i) {
        char c = s[i];
        if (c == '.') { has_dot = 1; last_dot = i; }
        else if (!is_domain_char(c)) break;
        dom_len++;
    }
    if (!has_dot || dom_len < 3) return 0;

    /* TLD must be at least 2 alpha chars */
    size_t tld_start = last_dot + 1;
    size_t tld_len = 0;
    for (size_t i = tld_start; i < dom_start + dom_len; ++i) {
        if (!is_tld_char(s[i])) break;
        tld_len++;
    }
    if (tld_len < 2) return 0;

    *out_len = dom_start + dom_len;
    return 1;
}

/* Domain: something.tld */
static int match_domain(const char *s, size_t len, size_t *out_len) {
    if (len < 4) return 0;
    int has_dot = 0;
    size_t last_dot = 0;
    size_t i = 0;
    for (; i < len; ++i) {
        char c = s[i];
        if (c == '.') { has_dot = 1; last_dot = i; }
        else if (!is_domain_char(c)) break;
    }
    if (!has_dot || i < 4) return 0;

    /* TLD must be at least 2 alpha chars */
    size_t tld_start = last_dot + 1;
    size_t tld_len = 0;
    for (size_t j = tld_start; j < i; ++j) {
        if (!is_tld_char(s[j])) break;
        tld_len++;
    }
    if (tld_len < 2) return 0;

    *out_len = i;
    return 1;
}

/* URL: http(s)://domain[/path] */
static int match_url(const char *s, size_t len, size_t *out_len) {
    size_t i = 0;
    /* Scheme */
    if (len - i >= 7 && (memcmp(s + i, "http://", 7) == 0 || memcmp(s + i, "HTTP://", 7) == 0)) i += 7;
    else if (len - i >= 8 && (memcmp(s + i, "https://", 8) == 0 || memcmp(s + i, "HTTPS://", 8) == 0)) i += 8;
    else if (len - i >= 6 && (memcmp(s + i, "ftp://", 6) == 0 || memcmp(s + i, "FTP://", 6) == 0)) i += 6;
    else return 0;

    /* Domain/host part */
    while (i < len) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == '\'' || c == '<' || c == '>' || c == ')' || c == ']' || c == '}')
            break;
        ++i;
    }
    if (i < 10) return 0; /* minimum http://a.co */
    *out_len = i;
    return 1;
}

/* Date: YYYY-MM-DD, DD/MM/YYYY, MM/DD/YYYY, YYYY/MM/DD, DD-MM-YYYY, etc. */
static int match_date(const char *s, size_t len, size_t *out_len) {
    if (len < 8) return 0;
    int y1 = 0, y2 = 0, m1 = 0, m2 = 0, d1 = 0, d2 = 0;
    char sep1 = 0, sep2 = 0;

    /* Try YYYY-MM-DD or YYYY/MM/DD */
    if (len >= 10 && s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9' &&
        s[2] >= '0' && s[2] <= '9' && s[3] >= '0' && s[3] <= '9' &&
        (s[4] == '-' || s[4] == '/') &&
        s[5] >= '0' && s[5] <= '9' && s[6] >= '0' && s[6] <= '9' &&
        s[7] == s[4] &&
        s[8] >= '0' && s[8] <= '9' && s[9] >= '0' && s[9] <= '9') {
        y1 = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0');
        m1 = (s[5]-'0')*10 + (s[6]-'0');
        d1 = (s[8]-'0')*10 + (s[9]-'0');
        if (y1 >= 1900 && y1 <= 2100 && m1 >= 1 && m1 <= 12 && d1 >= 1 && d1 <= 31) {
            *out_len = 10;
            return 1;
        }
    }

    /* Try DD/MM/YYYY or MM/DD/YYYY or DD-MM-YYYY */
    if (len >= 10 && s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9' &&
        (s[2] == '/' || s[2] == '-') &&
        s[3] >= '0' && s[3] <= '9' && s[4] >= '0' && s[4] <= '9' &&
        s[5] == s[2] &&
        s[6] >= '0' && s[6] <= '9' && s[7] >= '0' && s[7] <= '9' &&
        s[8] >= '0' && s[8] <= '9' && s[9] >= '0' && s[9] <= '9') {
        int a = (s[0]-'0')*10 + (s[1]-'0');
        int b = (s[3]-'0')*10 + (s[4]-'0');
        int c = (s[6]-'0')*1000 + (s[7]-'0')*100 + (s[8]-'0')*10 + (s[9]-'0');
        if (c >= 1900 && c <= 2100) {
            /* Try DD/MM/YYYY */
            if (a >= 1 && a <= 31 && b >= 1 && b <= 12) { *out_len = 10; return 1; }
            /* Try MM/DD/YYYY */
            if (b >= 1 && b <= 31 && a >= 1 && a <= 12) { *out_len = 10; return 1; }
        }
    }

    return 0;
}

/* Time: HH:MM:SS or HH:MM */
static int match_time(const char *s, size_t len, size_t *out_len) {
    if (len < 5) return 0;
    if (s[0] >= '0' && s[0] <= '2' && s[1] >= '0' && s[1] <= '9' && s[2] == ':' &&
        s[3] >= '0' && s[3] <= '5' && s[4] >= '0' && s[4] <= '9') {
        int hh = (s[0]-'0')*10 + (s[1]-'0');
        if (hh > 23) return 0;
        if (len >= 8 && s[5] == ':' && s[6] >= '0' && s[6] <= '5' && s[7] >= '0' && s[7] <= '9') {
            *out_len = 8;
            return 1;
        }
        *out_len = 5;
        return 1;
    }
    return 0;
}

/* Phone number: +X (XXX) XXX-XXXX or XXX-XXX-XXXX or similar */
static int match_phone(const char *s, size_t len, size_t *out_len) {
    size_t i = 0;
    int digits = 0;
    if (i < len && s[i] == '+') ++i;
    while (i < len) {
        char c = s[i];
        if (c >= '0' && c <= '9') { ++digits; ++i; }
        else if (c == ' ' || c == '-' || c == '.' || c == '(' || c == ')') { ++i; }
        else break;
    }
    if (digits >= 7 && digits <= 15) {
        *out_len = i;
        return 1;
    }
    return 0;
}

/* Crypto wallet addresses:
 * Bitcoin: 1, 3, or bc1 prefix, 26-62 chars
 * Ethereum: 0x + 40 hex chars
 * Monero: 4/8 + 94-95 base58 chars
 */
static int match_crypto(const char *s, size_t len, size_t *out_len) {
    if (len < 26) return 0;

    /* Bitcoin: starts with 1, 3, or bc1 */
    if ((s[0] == '1' || s[0] == '3') && len >= 26) {
        size_t i = 1;
        while (i < len && i < 62) {
            char c = s[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
                break;
            ++i;
        }
        if (i >= 26 && i <= 62) { *out_len = i; return 1; }
    }
    if (len >= 3 && s[0] == 'b' && s[1] == 'c' && s[2] == '1') {
        size_t i = 3;
        while (i < len && i < 90) {
            char c = s[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
                break;
            ++i;
        }
        if (i >= 26) { *out_len = i; return 1; }
    }

    /* Ethereum: 0x + 40 hex chars */
    if (len >= 42 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        size_t i = 2;
        while (i < len && i < 42) {
            char c = s[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                break;
            ++i;
        }
        if (i == 42) { *out_len = 42; return 1; }
    }

    /* Monero: starts with 4 or 8, 95-106 base58 chars */
    if ((s[0] == '4' || s[0] == '8') && len >= 95) {
        size_t i = 1;
        while (i < len && i < 106) {
            char c = s[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
                break;
            ++i;
        }
        if (i >= 95 && i <= 106) { *out_len = i; return 1; }
    }

    return 0;
}

/* ---- Pattern scan entry point ---- */
typedef int (*pattern_fn)(const char *s, size_t len, size_t *out_len);

typedef struct {
    const char *name;
    pattern_fn fn;
} pattern_def;

static const pattern_def g_patterns[] = {
    {"IPv4 Address",     match_ipv4},
    {"IPv6 Address",     match_ipv6},
    {"Email",            match_email},
    {"Domain",           match_domain},
    {"URL",              match_url},
    {"Date",             match_date},
    {"Time",             match_time},
    {"Phone Number",     match_phone},
    {"Crypto Wallet",    match_crypto},
};
#define NUM_PATTERNS (sizeof(g_patterns) / sizeof(g_patterns[0]))

static void scan_patterns(str_builder *sb, unsigned int mask) {
    if (!g_buf) {
        sb_printf(sb, "No file loaded.\r\n");
        return;
    }
    if (mask == 0) {
        sb_printf(sb, "No pattern types selected. Check at least one checkbox.\r\n");
        return;
    }

    /* Counters per pattern */
    size_t counts[NUM_PATTERNS];
    memset(counts, 0, sizeof(counts));
    size_t line_count = 0;

    /* Build a quick-reject bitmap: which first bytes can start any enabled pattern?
     * Patterns that can start with any byte (IPv4, IPv6, phone, crypto) set all bits.
     * Others (email, domain, URL, date, time) have specific first-char constraints. */
    unsigned char quick_reject[256] = {0};
    for (int p = 0; p < (int)NUM_PATTERNS; ++p) {
        if (!(mask & (1u << p))) continue;
        switch (p) {
            case 0: /* IPv4 — starts with digit */
                for (int c = '0'; c <= '9'; ++c) quick_reject[c] = 1;
                break;
            case 1: /* IPv6 — starts with hex digit or colon */
                for (int c = '0'; c <= '9'; ++c) quick_reject[c] = 1;
                for (int c = 'a'; c <= 'f'; ++c) quick_reject[c] = 1;
                for (int c = 'A'; c <= 'F'; ++c) quick_reject[c] = 1;
                quick_reject[':'] = 1;
                break;
            case 2: /* Email — starts with alnum or ._+-% */
                for (int c = '0'; c <= '9'; ++c) quick_reject[c] = 1;
                for (int c = 'a'; c <= 'z'; ++c) quick_reject[c] = 1;
                for (int c = 'A'; c <= 'Z'; ++c) quick_reject[c] = 1;
                quick_reject['.'] = quick_reject['_'] = quick_reject['-'] = 1;
                quick_reject['+'] = quick_reject['%'] = 1;
                break;
            case 3: /* Domain — starts with alnum or hyphen */
                for (int c = '0'; c <= '9'; ++c) quick_reject[c] = 1;
                for (int c = 'a'; c <= 'z'; ++c) quick_reject[c] = 1;
                for (int c = 'A'; c <= 'Z'; ++c) quick_reject[c] = 1;
                quick_reject['-'] = 1;
                break;
            case 4: /* URL — starts with h/H/f/F */
                quick_reject['h'] = quick_reject['H'] = 1;
                quick_reject['f'] = quick_reject['F'] = 1;
                break;
            case 5: /* Date — starts with digit */
                for (int c = '0'; c <= '9'; ++c) quick_reject[c] = 1;
                break;
            case 6: /* Time — starts with digit 0-2 */
                quick_reject['0'] = quick_reject['1'] = quick_reject['2'] = 1;
                break;
            case 7: /* Phone — starts with digit or + */
                for (int c = '0'; c <= '9'; ++c) quick_reject[c] = 1;
                quick_reject['+'] = 1;
                break;
            case 8: /* Crypto — starts with 1,3,b,0,4,8 */
                quick_reject['1'] = quick_reject['3'] = quick_reject['b'] = 1;
                quick_reject['0'] = quick_reject['4'] = quick_reject['8'] = 1;
                break;
        }
    }

    /* Scan the file as ASCII text */
    size_t i = 0;
    while (i < g_size) {
        /* Find start of a printable run */
        while (i < g_size && g_buf[i] < 32 && g_buf[i] != '\t') ++i;
        if (i >= g_size) break;

        /* Collect the run */
        size_t run_start = i;
        while (i < g_size && (g_buf[i] >= 32 || g_buf[i] == '\t')) ++i;
        size_t run_len = i - run_start;
        if (run_len < 4) continue;

        /* Try each pattern at every position within the run */
        for (size_t pos = 0; pos < run_len; ) {
            /* Quick-reject: skip bytes that can't start any enabled pattern */
            if (!quick_reject[g_buf[run_start + pos]]) { ++pos; continue; }
            int matched = 0;
            for (int p = 0; p < (int)NUM_PATTERNS; ++p) {
                if (!(mask & (1u << p))) continue;
                size_t match_len = 0;
                if (g_patterns[p].fn((const char *)(g_buf + run_start + pos), run_len - pos, &match_len)) {
                    if (match_len > 0) {
                        if (line_count < MAX_OUTPUT_LINES) {
                            sb_printf(sb, "0x%08zX [%s]: ", run_start + pos, g_patterns[p].name);
                            append_sanitized(sb, (const char *)(g_buf + run_start + pos), match_len);
                            sb_printf(sb, "\r\n");
                            line_count++;
                        }
                        counts[p]++;
                        pos += match_len;
                        matched = 1;
                        break;
                    }
                }
            }
            if (!matched) ++pos;
        }
    }

    if (line_count >= MAX_OUTPUT_LINES)
        sb_printf(sb, "\r\n(Output truncated at %d lines)\r\n", MAX_OUTPUT_LINES);
    sb_printf(sb, "\r\n--- Summary ---\r\n");
    for (int p = 0; p < (int)NUM_PATTERNS; ++p) {
        if (mask & (1u << p))
            sb_printf(sb, "  %-16s: %zu\r\n", g_patterns[p].name, counts[p]);
    }
}

static void build_hex_dump(str_builder *sb, size_t start, size_t length) {
    if (!g_buf) {
        sb_printf(sb, "No file loaded.\r\n");
        return;
    }
    if (start >= g_size) {
        sb_printf(sb, "Offset out of range.\r\n");
        return;
    }
    if (length == 0) {
        sb_printf(sb, "Length must be greater than zero.\r\n");
        return;
    }
    if (length > MAX_HEX_DUMP_BYTES) length = MAX_HEX_DUMP_BYTES;
    size_t end = start + length;
    if (end < start || end > g_size) end = g_size;

    sb_printf(sb, "--- Hex Dump [0x%zX - 0x%zX] ---\r\n", start, end - 1);
    /* Build each line in a stack buffer, then emit once — avoids 17+ sb_printf calls per line */
    char line[128];
    for (size_t i = start; i < end; i += 16) {
        int pos = snprintf(line, sizeof(line), "%08zX  ", i);
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < end) {
                pos += snprintf(line + pos, sizeof(line) - pos, "%02X ", g_buf[i+j]);
            } else {
                pos += snprintf(line + pos, sizeof(line) - pos, "   ");
            }
            if (j == 7) {
                line[pos++] = ' ';
                line[pos] = '\0';
            }
        }
        pos += snprintf(line + pos, sizeof(line) - pos, " |");
        for (size_t j = 0; j < 16 && i + j < end; ++j) {
            uint8_t c = g_buf[i+j];
            line[pos++] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        line[pos++] = '|';
        line[pos++] = '\r';
        line[pos++] = '\n';
        line[pos] = '\0';
        sb_append_cstr(sb, line);
    }
}

static void build_general_info(str_builder *sb) {
    if (!g_buf) {
        sb_printf(sb, "No file loaded.\r\n");
        return;
    }
    sb_printf(sb, "Path: %s\r\n", g_path);
    sb_printf(sb, "Size: %zu bytes\r\n", g_size);
    sb_printf(sb, "Entropy: %.4f bits/byte\r\n", calc_entropy(g_buf, g_size));

    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, g_buf, g_size);
    uint8_t hash[32];
    sha256_final(&ctx, hash);
    sb_append_cstr(sb, "SHA-256: ");
    for (int i = 0; i < 32; ++i) sb_printf(sb, "%02x", hash[i]);
    sb_append_cstr(sb, "\r\n");

    if (is_pe(g_buf, g_size)) sb_append_cstr(sb, "Type: PE (Portable Executable)\r\n");
    else sb_append_cstr(sb, "Type: Unknown / not a PE file\r\n");
}

static int get_pe_headers(const uint8_t *buf, size_t size,
                          const IMAGE_DOS_HEADER **out_dos,
                          const IMAGE_FILE_HEADER **out_file,
                          const IMAGE_OPTIONAL_HEADER32 **out_opt32,
                          const IMAGE_OPTIONAL_HEADER64 **out_opt64,
                          const IMAGE_SECTION_HEADER **out_sections,
                          WORD *out_num_sections,
                          int *out_is64) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return 0;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)buf;
    if (dos->e_magic != 0x5A4D) return 0;
    DWORD lfanew = (DWORD)dos->e_lfanew;
    if (lfanew < sizeof(IMAGE_DOS_HEADER) || lfanew > size) return 0;
    if (size - lfanew < 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD)) return 0;

    DWORD pe_sig = *(const DWORD *)(buf + lfanew);
    if (pe_sig != IMAGE_NT_SIGNATURE) return 0;

    const IMAGE_FILE_HEADER *file = (const IMAGE_FILE_HEADER *)(buf + lfanew + 4);
    size_t opt_offset = lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
    if (opt_offset > size || size - opt_offset < sizeof(WORD)) return 0;

    WORD magic = *(const WORD *)(buf + opt_offset);
    size_t opt_size = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        opt_size = sizeof(IMAGE_OPTIONAL_HEADER32);
        *out_is64 = 0;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        opt_size = sizeof(IMAGE_OPTIONAL_HEADER64);
        *out_is64 = 1;
    } else {
        return 0;
    }

    if (size - opt_offset < opt_size) return 0;
    if (file->SizeOfOptionalHeader < (WORD)opt_size) return 0;

    WORD num_sections = file->NumberOfSections;
    if (num_sections > 256) num_sections = 256;
    size_t sec_table_offset = opt_offset + file->SizeOfOptionalHeader;
    size_t sec_table_size = (size_t)num_sections * sizeof(IMAGE_SECTION_HEADER);
    if (sec_table_size / sizeof(IMAGE_SECTION_HEADER) != num_sections) return 0;
    if (sec_table_offset > size || size - sec_table_offset < sec_table_size) return 0;

    *out_dos = dos;
    *out_file = file;
    *out_opt32 = (const IMAGE_OPTIONAL_HEADER32 *)(buf + opt_offset);
    *out_opt64 = (const IMAGE_OPTIONAL_HEADER64 *)(buf + opt_offset);
    *out_sections = (const IMAGE_SECTION_HEADER *)(buf + sec_table_offset);
    *out_num_sections = num_sections;
    return 1;
}

static void build_pe_info(str_builder *sb) {
    if (!g_buf) {
        sb_printf(sb, "No file loaded.\r\n");
        return;
    }
    if (!ensure_pe_cache()) {
        sb_printf(sb, "Not a valid PE file.\r\n");
        return;
    }

    const IMAGE_FILE_HEADER *file = g_pe_cache.file;
    const IMAGE_OPTIONAL_HEADER32 *opt32 = g_pe_cache.opt32;
    const IMAGE_OPTIONAL_HEADER64 *opt64 = g_pe_cache.opt64;
    const IMAGE_SECTION_HEADER *sections = g_pe_cache.sections;
    WORD num_sections = g_pe_cache.num_sections;
    int is64 = g_pe_cache.is64;

    sb_printf(sb, "PE Signature: 0x%08X\r\n", IMAGE_NT_SIGNATURE);
    sb_printf(sb, "Machine: %s\r\n", machine_name(file->Machine));
    sb_printf(sb, "Number of sections: %u\r\n", (unsigned)num_sections);
    sb_printf(sb, "Timestamp: 0x%08X\r\n", (unsigned)file->TimeDateStamp);
    sb_printf(sb, "Characteristics: 0x%04X\r\n", (unsigned)file->Characteristics);

    DWORD entry_rva = 0;
    WORD subsystem = 0;
    ULONGLONG image_base = 0;
    if (is64) {
        entry_rva = opt64->AddressOfEntryPoint;
        subsystem = opt64->Subsystem;
        image_base = opt64->ImageBase;
        sb_printf(sb, "Image base: 0x%llX\r\n", image_base);
        sb_printf(sb, "Subsystem: %s\r\n", subsystem_name(subsystem));
        size_t entry_off = rva_to_offset(entry_rva, sections, num_sections);
        if (entry_off == SIZE_MAX)
            sb_printf(sb, "Entry point RVA: 0x%08X (not mapped to file)\r\n", entry_rva);
        else
            sb_printf(sb, "Entry point RVA: 0x%08X (file offset 0x%08zX)\r\n", entry_rva, entry_off);
        sb_printf(sb, "Section alignment: 0x%08X\r\n", opt64->SectionAlignment);
        sb_printf(sb, "File alignment: 0x%08X\r\n", opt64->FileAlignment);
        sb_printf(sb, "Image size: 0x%08X\r\n", opt64->SizeOfImage);
        sb_printf(sb, "Headers size: 0x%08X\r\n", opt64->SizeOfHeaders);
        sb_append_cstr(sb, "\r\nData directories:\r\n");
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            sb_printf(sb, "  [%2d] %-18s RVA: 0x%08X  Size: 0x%08X\r\n",
                i, dir_name(i), opt64->DataDirectory[i].VirtualAddress, opt64->DataDirectory[i].Size);
        }
    } else {
        entry_rva = opt32->AddressOfEntryPoint;
        subsystem = opt32->Subsystem;
        image_base = opt32->ImageBase;
        sb_printf(sb, "Image base: 0x%llX\r\n", image_base);
        sb_printf(sb, "Subsystem: %s\r\n", subsystem_name(subsystem));
        size_t entry_off = rva_to_offset(entry_rva, sections, num_sections);
        if (entry_off == SIZE_MAX)
            sb_printf(sb, "Entry point RVA: 0x%08X (not mapped to file)\r\n", entry_rva);
        else
            sb_printf(sb, "Entry point RVA: 0x%08X (file offset 0x%08zX)\r\n", entry_rva, entry_off);
        sb_printf(sb, "Section alignment: 0x%08X\r\n", opt32->SectionAlignment);
        sb_printf(sb, "File alignment: 0x%08X\r\n", opt32->FileAlignment);
        sb_printf(sb, "Image size: 0x%08X\r\n", opt32->SizeOfImage);
        sb_printf(sb, "Headers size: 0x%08X\r\n", opt32->SizeOfHeaders);
        sb_append_cstr(sb, "\r\nData directories:\r\n");
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            sb_printf(sb, "  [%2d] %-18s RVA: 0x%08X  Size: 0x%08X\r\n",
                i, dir_name(i), opt32->DataDirectory[i].VirtualAddress, opt32->DataDirectory[i].Size);
        }
    }

    sb_append_cstr(sb, "\r\nSections:\r\n");
    for (WORD i = 0; i < num_sections; ++i) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);
        DWORD vsize = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        sb_printf(sb, "  %-8s  RVA: 0x%08X  VSize: 0x%08X  Raw: 0x%08X  RawSize: 0x%08X  Flags: 0x%08X\r\n",
            name, sections[i].VirtualAddress, vsize,
            sections[i].PointerToRawData, sections[i].SizeOfRawData,
            sections[i].Characteristics);
    }
}

static size_t bounded_cstr(char *dst, size_t dst_size, size_t off, size_t max_len) {
    if (dst_size == 0) return 0;
    if (!g_buf || off >= g_size) { dst[0] = '\0'; return 0; }
    size_t avail = g_size - off;
    if (max_len > avail) max_len = avail;
    if (max_len > dst_size - 1) max_len = dst_size - 1;
    size_t n = 0;
    while (n < max_len && g_buf[off + n] != '\0') {
        dst[n] = (char)g_buf[off + n];
        n++;
    }
    dst[n] = '\0';
    return n;
}

static void build_imports(str_builder *sb) {
    if (!g_buf) {
        sb_printf(sb, "No file loaded.\r\n");
        return;
    }
    if (!ensure_pe_cache()) {
        sb_printf(sb, "Not a valid PE file.\r\n");
        return;
    }

    const IMAGE_OPTIONAL_HEADER32 *opt32 = g_pe_cache.opt32;
    const IMAGE_OPTIONAL_HEADER64 *opt64 = g_pe_cache.opt64;
    const IMAGE_SECTION_HEADER *sections = g_pe_cache.sections;
    WORD num_sections = g_pe_cache.num_sections;
    int is64 = g_pe_cache.is64;

    IMAGE_DATA_DIRECTORY imp_dir;
    if (is64) imp_dir = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    else imp_dir = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) {
        sb_printf(sb, "No import table.\r\n");
        return;
    }

    size_t imp_off = rva_to_offset(imp_dir.VirtualAddress, sections, num_sections);
    size_t imp_size = imp_dir.Size;
    if (imp_off == SIZE_MAX || imp_size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        sb_printf(sb, "Import directory invalid.\r\n");
        return;
    }
    if (imp_size > g_size - imp_off) {
        sb_printf(sb, "Import directory out of bounds.\r\n");
        return;
    }

    size_t max_count = imp_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    const IMAGE_IMPORT_DESCRIPTOR *imp = (const IMAGE_IMPORT_DESCRIPTOR *)(g_buf + imp_off);

    for (size_t idx = 0; idx < max_count; ++idx) {
        if (imp[idx].Characteristics == 0) break;

        char dll_name[256] = {0};
        size_t name_off = rva_to_offset(imp[idx].Name, sections, num_sections);
        if (name_off != SIZE_MAX) {
            bounded_cstr(dll_name, sizeof(dll_name), name_off, 256);
        }
        if (dll_name[0] == '\0') snprintf(dll_name, sizeof(dll_name), "<unnamed:%lu>", (unsigned long)idx);
        sb_printf(sb, "\r\n%s\r\n", dll_name);

        DWORD thunk_rva = imp[idx].OriginalFirstThunk ? imp[idx].OriginalFirstThunk : imp[idx].FirstThunk;
        if (thunk_rva == 0) {
            sb_append_cstr(sb, "  (no thunk data)\r\n");
            continue;
        }

        size_t thunk_off = rva_to_offset(thunk_rva, sections, num_sections);
        if (thunk_off == SIZE_MAX) {
            thunk_rva = imp[idx].FirstThunk;
            if (thunk_rva == 0) {
                sb_append_cstr(sb, "  (thunk RVA not mapped)\r\n");
                continue;
            }
            thunk_off = rva_to_offset(thunk_rva, sections, num_sections);
            if (thunk_off == SIZE_MAX) {
                sb_append_cstr(sb, "  (thunk RVA not mapped)\r\n");
                continue;
            }
        }

        if (is64) {
            for (size_t j = 0; ; ++j) {
                if (j > g_size / sizeof(ULONGLONG)) break; /* overflow guard */
                size_t addr_off = thunk_off + j * sizeof(ULONGLONG);
                if (addr_off + sizeof(ULONGLONG) > g_size) break;
                ULONGLONG addr = *(const ULONGLONG *)(g_buf + addr_off);
                if (addr == 0) break;
                if (addr & IMAGE_ORDINAL_FLAG64) {
                    sb_printf(sb, "  Ordinal %llu\r\n", (unsigned long long)IMAGE_ORDINAL64(addr));
                } else {
                    size_t hint_off = rva_to_offset((DWORD)addr, sections, num_sections);
                    char func_name[256] = {0};
                    if (hint_off != SIZE_MAX && hint_off + 2 > hint_off && hint_off + 2 < g_size) {
                        bounded_cstr(func_name, sizeof(func_name), hint_off + 2, 256);
                    }
                    sb_printf(sb, "  %s\r\n", func_name[0] ? func_name : "<unnamed>");
                }
            }
        } else {
            for (size_t j = 0; ; ++j) {
                if (j > g_size / sizeof(DWORD)) break; /* overflow guard */
                size_t addr_off = thunk_off + j * sizeof(DWORD);
                if (addr_off + sizeof(DWORD) > g_size) break;
                DWORD addr = *(const DWORD *)(g_buf + addr_off);
                if (addr == 0) break;
                if (addr & IMAGE_ORDINAL_FLAG32) {
                    sb_printf(sb, "  Ordinal %u\r\n", (unsigned)IMAGE_ORDINAL32(addr));
                } else {
                    size_t hint_off = rva_to_offset(addr, sections, num_sections);
                    char func_name[256] = {0};
                    if (hint_off != SIZE_MAX && hint_off + 2 > hint_off && hint_off + 2 < g_size) {
                        bounded_cstr(func_name, sizeof(func_name), hint_off + 2, 256);
                    }
                    sb_printf(sb, "  %s\r\n", func_name[0] ? func_name : "<unnamed>");
                }
            }
        }
    }
}

static void build_exports(str_builder *sb) {
    if (!g_buf) {
        sb_printf(sb, "No file loaded.\r\n");
        return;
    }
    if (!ensure_pe_cache()) {
        sb_printf(sb, "Not a valid PE file.\r\n");
        return;
    }

    const IMAGE_OPTIONAL_HEADER32 *opt32 = g_pe_cache.opt32;
    const IMAGE_OPTIONAL_HEADER64 *opt64 = g_pe_cache.opt64;
    const IMAGE_SECTION_HEADER *sections = g_pe_cache.sections;
    WORD num_sections = g_pe_cache.num_sections;
    int is64 = g_pe_cache.is64;

    IMAGE_DATA_DIRECTORY exp_dir;
    if (is64) exp_dir = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    else exp_dir = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exp_dir.VirtualAddress == 0 || exp_dir.Size == 0) {
        sb_printf(sb, "No export table.\r\n");
        return;
    }

    size_t exp_off = rva_to_offset(exp_dir.VirtualAddress, sections, num_sections);
    if (exp_off == SIZE_MAX || sizeof(IMAGE_EXPORT_DIRECTORY) > g_size - exp_off) {
        sb_printf(sb, "Export directory invalid.\r\n");
        return;
    }

    const IMAGE_EXPORT_DIRECTORY *exp = (const IMAGE_EXPORT_DIRECTORY *)(g_buf + exp_off);
    sb_printf(sb, "Export directory at RVA 0x%08X\r\n", exp_dir.VirtualAddress);
    sb_printf(sb, "  Name: 0x%08X\r\n", exp->Name);
    sb_printf(sb, "  Base: %u\r\n", (unsigned)exp->Base);
    sb_printf(sb, "  NumberOfFunctions: %u\r\n", (unsigned)exp->NumberOfFunctions);
    sb_printf(sb, "  NumberOfNames: %u\r\n", (unsigned)exp->NumberOfNames);

    size_t funcs_off = rva_to_offset(exp->AddressOfFunctions, sections, num_sections);
    size_t names_off = rva_to_offset(exp->AddressOfNames, sections, num_sections);
    size_t ords_off  = rva_to_offset(exp->AddressOfNameOrdinals, sections, num_sections);

    if (funcs_off == SIZE_MAX) {
        sb_printf(sb, "Function array not mapped.\r\n");
        return;
    }

    DWORD num_funcs = exp->NumberOfFunctions;
    if (num_funcs > 65536) num_funcs = 65536;

    if (exp->NumberOfNames == 0) {
        /* Ordinal-only exports */
        for (DWORD i = 0; i < num_funcs; ++i) {
            if (funcs_off + (i + 1) * sizeof(DWORD) > g_size) break;
            DWORD rva = ((const DWORD *)(g_buf + funcs_off))[i];
            if (rva == 0) continue;
            sb_printf(sb, "  Ordinal %u -> RVA 0x%08X\r\n", (unsigned)(exp->Base + i), rva);
        }
        return;
    }

    if (names_off == SIZE_MAX || ords_off == SIZE_MAX ||
        exp->NumberOfNames * sizeof(DWORD) > g_size - names_off ||
        exp->NumberOfNames * sizeof(WORD) > g_size - ords_off) {
        sb_printf(sb, "Export name/ordinal arrays invalid.\r\n");
        return;
    }

    const DWORD *names = (const DWORD *)(g_buf + names_off);
    const WORD *ords = (const WORD *)(g_buf + ords_off);
    const DWORD *funcs = (const DWORD *)(g_buf + funcs_off);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        if (names_off + i * sizeof(DWORD) + sizeof(DWORD) > g_size) break;
        if (ords_off + i * sizeof(WORD) + sizeof(WORD) > g_size) break;
        DWORD name_rva = names[i];
        WORD ord = ords[i];
        if ((DWORD)ord >= num_funcs) continue;
        if (funcs_off + ord * sizeof(DWORD) + sizeof(DWORD) > g_size) continue;
        DWORD func_rva = funcs[ord];
        if (func_rva == 0) continue;

        char func_name[256] = {0};
        size_t name_off = rva_to_offset(name_rva, sections, num_sections);
        if (name_off != SIZE_MAX) bounded_cstr(func_name, sizeof(func_name), name_off, 256);
        sb_printf(sb, "  %s (ord %u) -> RVA 0x%08X\r\n",
            func_name[0] ? func_name : "<unnamed>", (unsigned)(exp->Base + ord), func_rva);
    }
}

static void refresh_all(void) {
    str_builder sb;
    sb_init(&sb);
    build_general_info(&sb);
    set_edit_text(g_hEditGeneral, sb.buf ? sb.buf : "");
    sb_free(&sb);

    sb_init(&sb);
    build_pe_info(&sb);
    set_edit_text(g_hEditPE, sb.buf ? sb.buf : "");
    sb_free(&sb);

    sb_init(&sb);
    build_imports(&sb);
    set_edit_text(g_hEditImports, sb.buf ? sb.buf : "");
    sb_free(&sb);

    sb_init(&sb);
    build_exports(&sb);
    set_edit_text(g_hEditExports, sb.buf ? sb.buf : "");
    sb_free(&sb);

    set_edit_text(g_hEditStrings, "Press 'ASCII Strings' or 'Unicode Strings' to extract strings.\r\n");
    set_edit_text(g_hEditHex, "Set offset/length and press 'Hex Dump'.\r\n");
    set_edit_text(g_hEditPatterns, "Select pattern types and press 'Scan Patterns'.\r\n");
}

static void open_file(void) {
    char filename[MAX_PATH] = {0};
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMain;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "All Files\0*.*\0PE Files\0*.exe;*.dll;*.sys;*.scr;*.ocx\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (GetOpenFileNameA(&ofn)) {
        if (g_buf) { free(g_buf); g_buf = NULL; g_size = 0; }
        invalidate_pe_cache();
        size_t sz = 0;
        uint8_t *buf = read_file(filename, &sz);
        if (!buf && sz > 0) {
            MessageBoxA(g_hMain, "Failed to read file.", "Error", MB_OK | MB_ICONERROR);
            set_status("Failed to read file.");
            return;
        }
        /* Empty files are valid: read_file returns NULL with sz == 0. */
        if (sz == 0) {
            if (buf) free(buf);
            buf = NULL;
        }
        g_buf = buf;
        g_size = sz;
        snprintf(g_path, sizeof(g_path), "%s", filename);
        SetWindowTextA(g_hPath, g_path);
        set_status("Loaded %zu bytes", g_size);
        refresh_all();
    }
}

static void show_tab(int idx) {
    HWND edits[TAB_COUNT] = { g_hEditGeneral, g_hEditPE, g_hEditImports, g_hEditExports, g_hEditStrings, g_hEditHex, g_hEditPatterns };
    for (int i = 0; i < TAB_COUNT; ++i) {
        ShowWindow(edits[i], (i == idx) ? SW_SHOW : SW_HIDE);
    }

    int isStrings = (idx == 4);
    int isHex = (idx == 5);
    int isPatterns = (idx == 6);

    /* Hide all tab-specific controls first to avoid overlap artifacts */
    ShowWindow(g_hLblMinLen, SW_HIDE);
    ShowWindow(g_hEditMinLen, SW_HIDE);
    ShowWindow(g_hBtnAscii, SW_HIDE);
    ShowWindow(g_hBtnUnicode, SW_HIDE);
    ShowWindow(g_hLblStrFilter, SW_HIDE);
    ShowWindow(g_hEditStrFilter, SW_HIDE);
    ShowWindow(g_hLblHexOffset, SW_HIDE);
    ShowWindow(g_hEditHexOffset, SW_HIDE);
    ShowWindow(g_hLblHexLen, SW_HIDE);
    ShowWindow(g_hEditHexLen, SW_HIDE);
    ShowWindow(g_hBtnHexDump, SW_HIDE);
    ShowWindow(g_hBtnScanPatterns, SW_HIDE);
    for (int p = 0; p < (int)NUM_PATTERNS; ++p) {
        if (g_hChkPatterns[p]) ShowWindow(g_hChkPatterns[p], SW_HIDE);
    }

    /* Show only the relevant set */
    if (isStrings) {
        ShowWindow(g_hLblMinLen, SW_SHOW);
        ShowWindow(g_hEditMinLen, SW_SHOW);
        ShowWindow(g_hBtnAscii, SW_SHOW);
        ShowWindow(g_hBtnUnicode, SW_SHOW);
        ShowWindow(g_hLblStrFilter, SW_SHOW);
        ShowWindow(g_hEditStrFilter, SW_SHOW);
    } else if (isHex) {
        ShowWindow(g_hLblHexOffset, SW_SHOW);
        ShowWindow(g_hEditHexOffset, SW_SHOW);
        ShowWindow(g_hLblHexLen, SW_SHOW);
        ShowWindow(g_hEditHexLen, SW_SHOW);
        ShowWindow(g_hBtnHexDump, SW_SHOW);
    } else if (isPatterns) {
        ShowWindow(g_hBtnScanPatterns, SW_SHOW);
        for (int p = 0; p < (int)NUM_PATTERNS; ++p) {
            if (g_hChkPatterns[p]) ShowWindow(g_hChkPatterns[p], SW_SHOW);
        }
    }
}

/* Modern color scheme and metrics */
#define MARGIN          12
#define TOPBAR_H        32
#define CTRL_H          26
#define CTRL_MARGIN     8
#define STATUS_H        22
#define BTN_W           90
#define EDIT_MINLEN_W   48
#define EDIT_HEX_W      90

static HBRUSH g_hbrBack = NULL;
static HBRUSH g_hbrEdit = NULL;
static HFONT g_hFont = NULL;

static void create_controls(HWND hWnd, HINSTANCE hInst) {
    g_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    if (!g_hbrBack) g_hbrBack = CreateSolidBrush(RGB(245, 246, 247));
    if (!g_hbrEdit) g_hbrEdit = CreateSolidBrush(RGB(255, 255, 255));

    /* Top toolbar: path + browse */
    g_hPath = CreateWindowA("EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 100, TOPBAR_H, hWnd, NULL, hInst, NULL);
    SendMessageA(g_hPath, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hBrowse = CreateWindowA("BUTTON", "Browse...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        0, 0, BTN_W, TOPBAR_H, hWnd, (HMENU)IDC_BROWSE, hInst, NULL);
    SendMessageA(g_hBrowse, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    /* Tab control - clip children so overlapping edit panes don't bleed through */
    g_hTab = CreateWindowA(WC_TABCONTROL, "",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | TCS_MULTILINE | TCS_FIXEDWIDTH,
        0, 0, 100, 100, hWnd, (HMENU)IDC_TAB, hInst, NULL);
    SendMessageA(g_hTab, TCM_SETITEMSIZE, 0, MAKELPARAM(90, 24));
    SendMessageA(g_hTab, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    /* No subclass needed — tab-specific controls are now children of the main window */

    TCITEMA ti = {0};
    ti.mask = TCIF_TEXT;
    const char *tabs[] = {"General", "PE Info", "Imports", "Exports", "Strings", "Hex Dump", "Patterns"};
    for (int i = 0; i < TAB_COUNT; ++i) {
        ti.pszText = (char *)tabs[i];
        TabCtrl_InsertItem(g_hTab, i, &ti);
    }

    /* Output panes - children of the tab control so they are properly clipped and Z-ordered */
    DWORD editStyle = WS_CHILD | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                      ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY | WS_BORDER;

    g_hEditGeneral = CreateWindowA("EDIT", "", editStyle, 0, 0, 100, 100, g_hTab, (HMENU)IDC_EDIT_GENERAL, hInst, NULL);
    g_hEditPE      = CreateWindowA("EDIT", "", editStyle, 0, 0, 100, 100, g_hTab, (HMENU)IDC_EDIT_PE, hInst, NULL);
    g_hEditImports = CreateWindowA("EDIT", "", editStyle, 0, 0, 100, 100, g_hTab, (HMENU)IDC_EDIT_IMPORTS, hInst, NULL);
    g_hEditExports = CreateWindowA("EDIT", "", editStyle, 0, 0, 100, 100, g_hTab, (HMENU)IDC_EDIT_EXPORTS, hInst, NULL);
    g_hEditStrings = CreateWindowA("EDIT", "", editStyle, 0, 0, 100, 100, g_hTab, (HMENU)IDC_EDIT_STRINGS, hInst, NULL);
    g_hEditHex     = CreateWindowA("EDIT", "", editStyle, 0, 0, 100, 100, g_hTab, (HMENU)IDC_EDIT_HEX, hInst, NULL);
    g_hEditPatterns = CreateWindowA("EDIT", "", editStyle, 0, 0, 100, 100, g_hTab, (HMENU)IDC_EDIT_PATTERNS, hInst, NULL);

    HWND edits[TAB_COUNT] = {g_hEditGeneral, g_hEditPE, g_hEditImports, g_hEditExports, g_hEditStrings, g_hEditHex, g_hEditPatterns};
    for (int i = 0; i < TAB_COUNT; ++i) {
        SendMessageA(edits[i], WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(edits[i], EM_SETLIMITTEXT, (WPARAM)0x7FFFFFFE, 0);
    }

    /* Strings tab controls - children of the MAIN WINDOW so WM_COMMAND
     * reaches WndProc directly without needing tab subclass forwarding */
    g_hLblMinLen = CreateWindowA("STATIC", "Min len:",
        WS_CHILD | SS_LEFTNOWORDWRAP | SS_CENTERIMAGE,
        0, 0, 50, CTRL_H, hWnd, NULL, hInst, NULL);
    SendMessageA(g_hLblMinLen, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hEditMinLen = CreateWindowA("EDIT", "4",
        WS_CHILD | WS_BORDER | WS_TABSTOP | ES_NUMBER | ES_CENTER,
        0, 0, EDIT_MINLEN_W, CTRL_H, hWnd, (HMENU)IDC_EDIT_MINLEN, hInst, NULL);
    SendMessageA(g_hEditMinLen, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hBtnAscii = CreateWindowA("BUTTON", "ASCII Strings",
        WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
        0, 0, 100, CTRL_H, hWnd, (HMENU)IDC_BTN_ASCII, hInst, NULL);
    SendMessageA(g_hBtnAscii, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hBtnUnicode = CreateWindowA("BUTTON", "Unicode Strings",
        WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
        0, 0, 110, CTRL_H, hWnd, (HMENU)IDC_BTN_UNICODE, hInst, NULL);
    SendMessageA(g_hBtnUnicode, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    /* Strings filter */
    g_hLblStrFilter = CreateWindowA("STATIC", "Filter:",
        WS_CHILD | SS_LEFTNOWORDWRAP | SS_CENTERIMAGE,
        0, 0, 35, CTRL_H, hWnd, NULL, hInst, NULL);
    SendMessageA(g_hLblStrFilter, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hEditStrFilter = CreateWindowA("EDIT", "",
        WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
        0, 0, 120, CTRL_H, hWnd, (HMENU)IDC_EDIT_STRFILTER, hInst, NULL);
    SendMessageA(g_hEditStrFilter, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    /* Hex tab controls - children of the MAIN WINDOW, create hidden */
    g_hLblHexOffset = CreateWindowA("STATIC", "Offset:",
        WS_CHILD | SS_LEFTNOWORDWRAP | SS_CENTERIMAGE,
        0, 0, 40, CTRL_H, hWnd, NULL, hInst, NULL);
    SendMessageA(g_hLblHexOffset, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hEditHexOffset = CreateWindowA("EDIT", "0",
        WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ES_CENTER,
        0, 0, EDIT_HEX_W, CTRL_H, hWnd, (HMENU)IDC_EDIT_HEXOFF, hInst, NULL);
    SendMessageA(g_hEditHexOffset, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hLblHexLen = CreateWindowA("STATIC", "Len:",
        WS_CHILD | SS_LEFTNOWORDWRAP | SS_CENTERIMAGE,
        0, 0, 25, CTRL_H, hWnd, NULL, hInst, NULL);
    SendMessageA(g_hLblHexLen, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hEditHexLen = CreateWindowA("EDIT", "256",
        WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ES_CENTER,
        0, 0, EDIT_HEX_W, CTRL_H, hWnd, (HMENU)IDC_EDIT_HEXLEN, hInst, NULL);
    SendMessageA(g_hEditHexLen, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hBtnHexDump = CreateWindowA("BUTTON", "Hex Dump",
        WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
        0, 0, 80, CTRL_H, hWnd, (HMENU)IDC_BTN_HEXDUMP, hInst, NULL);
    SendMessageA(g_hBtnHexDump, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    /* Patterns tab controls */
    g_hBtnScanPatterns = CreateWindowA("BUTTON", "Scan Patterns",
        WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
        0, 0, 110, CTRL_H, hWnd, (HMENU)IDC_BTN_SCAN_PATTERNS, hInst, NULL);
    SendMessageA(g_hBtnScanPatterns, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    /* Pattern checkboxes - one per pattern type, all checked by default */
    for (int p = 0; p < (int)NUM_PATTERNS; ++p) {
        g_hChkPatterns[p] = CreateWindowA("BUTTON", g_patterns[p].name,
            WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
            0, 0, 140, CTRL_H, hWnd, (HMENU)(IDC_CHK_PATTERN_BASE + p), hInst, NULL);
        SendMessageA(g_hChkPatterns[p], WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hChkPatterns[p], BM_SETCHECK, BST_CHECKED, 0);
    }

    /* Status bar */
    g_hStatus = CreateWindowA(STATUSCLASSNAMEA, "Ready",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hWnd, NULL, hInst, NULL);
    SendMessageA(g_hStatus, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    show_tab(0);
}

static void reposition_controls(int w, int h) {
    int x = MARGIN;
    int y = MARGIN;
    int clientW = w - MARGIN * 2;

    if (clientW < 100 || h < 100) return;

    /* Top bar — position immediately, no repaint yet */
    MoveWindow(g_hPath, x, y, clientW - BTN_W - CTRL_MARGIN, TOPBAR_H, FALSE);
    MoveWindow(g_hBrowse, x + clientW - BTN_W, y, BTN_W, TOPBAR_H, FALSE);

    /* Tab control — MUST be positioned BEFORE we read its client rect.
     * MoveWindow with FALSE applies the new size immediately without repainting. */
    y += TOPBAR_H + CTRL_MARGIN;
    int tabY = y;
    int tabBottom = h - STATUS_H - MARGIN;
    int tabH = tabBottom - tabY;
    if (tabH < 50) tabH = 50;
    MoveWindow(g_hTab, x, tabY, clientW, tabH, FALSE);

    /* Now the tab has its correct size. Read the inner display area.
     * Edit panes and controls are children of the tab, so coordinates
     * are relative to the tab's client area (origin 0,0). */
    RECT rcTab;
    GetClientRect(g_hTab, &rcTab);
    TabCtrl_AdjustRect(g_hTab, FALSE, &rcTab);
    int innerX = rcTab.left;
    int innerY = rcTab.top;
    /* TabCtrl_AdjustRect can return negative values with some themes */
    if (innerX < 0) innerX = 0;
    if (innerY < 0) innerY = 0;
    int innerW = rcTab.right - rcTab.left;
    int innerH = rcTab.bottom - rcTab.top;

    /* Reserve bottom row for tab-specific controls */
    int editH = innerH - CTRL_H - CTRL_MARGIN;
    if (editH < 20) editH = 20;
    int ctrlY = innerY + editH + CTRL_MARGIN;

    /* Output panes — all get the same rectangle */
    HWND edits[7] = {g_hEditGeneral, g_hEditPE, g_hEditImports, g_hEditExports, g_hEditStrings, g_hEditHex, g_hEditPatterns};
    for (int i = 0; i < 7; ++i) {
        MoveWindow(edits[i], innerX, innerY, innerW, editH, FALSE);
    }

    /* Tab-specific controls are children of the main window, so coordinates
     * must be main-window-relative: add the tab's position (x, tabY). */
    int baseX = x + innerX;
    int baseY = tabY + ctrlY;

    /* Strings controls */
    int cx = baseX;
    int maxCx = baseX + innerW;
    MoveWindow(g_hLblMinLen, cx, baseY, 50, CTRL_H, FALSE); cx += 50 + CTRL_MARGIN;
    MoveWindow(g_hEditMinLen, cx, baseY, EDIT_MINLEN_W, CTRL_H, FALSE); cx += EDIT_MINLEN_W + CTRL_MARGIN;
    MoveWindow(g_hBtnAscii, cx, baseY, 100, CTRL_H, FALSE); cx += 100 + CTRL_MARGIN;
    MoveWindow(g_hBtnUnicode, cx, baseY, 110, CTRL_H, FALSE); cx += 110 + CTRL_MARGIN;
    MoveWindow(g_hLblStrFilter, cx, baseY, 35, CTRL_H, FALSE); cx += 35 + CTRL_MARGIN;
    int filterW = maxCx - cx;
    if (filterW < 60) filterW = 60;
    MoveWindow(g_hEditStrFilter, cx, baseY, filterW, CTRL_H, FALSE);

    /* Hex controls */
    cx = baseX;
    MoveWindow(g_hLblHexOffset, cx, baseY, 40, CTRL_H, FALSE); cx += 40 + CTRL_MARGIN;
    MoveWindow(g_hEditHexOffset, cx, baseY, EDIT_HEX_W, CTRL_H, FALSE); cx += EDIT_HEX_W + CTRL_MARGIN;
    MoveWindow(g_hLblHexLen, cx, baseY, 25, CTRL_H, FALSE); cx += 25 + CTRL_MARGIN;
    MoveWindow(g_hEditHexLen, cx, baseY, EDIT_HEX_W, CTRL_H, FALSE); cx += EDIT_HEX_W + CTRL_MARGIN;
    MoveWindow(g_hBtnHexDump, cx, baseY, 80, CTRL_H, FALSE);

    /* Patterns button and checkboxes */
    MoveWindow(g_hBtnScanPatterns, baseX, baseY, 110, CTRL_H, FALSE);
    int chkX = baseX + 120;
    int chkY = baseY;
    for (int p = 0; p < (int)NUM_PATTERNS; ++p) {
        if (g_hChkPatterns[p]) {
            MoveWindow(g_hChkPatterns[p], chkX, chkY, 140, CTRL_H, FALSE);
            chkX += 145;
            if (chkX + 140 > baseX + innerW) {
                chkX = baseX + 120;
                chkY += CTRL_H + 2;
            }
        }
    }

    /* Status bar */
    SendMessageA(g_hStatus, WM_SIZE, 0, 0);

    /* RedrawWindow with RDW_ALLCHILDREN reaches grandchildren (edit panes
     * inside the tab control).  InvalidateRect only hits direct children,
     * which is why the edit panes were never repainted after resize and
     * appeared to "paint on top of each other with no refresh".
     * Omit RDW_UPDATENOW — let the WM_PAINT cycle handle it asynchronously
     * to avoid synchronous repaint jank during window drag/resize. */
    RedrawWindow(g_hMain, NULL, NULL,
        RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            create_controls(hWnd, ((LPCREATESTRUCT)lParam)->hInstance);
            refresh_all();
            return 0;

        case WM_SIZE: {
            int w = LOWORD(lParam);
            int h = HIWORD(lParam);
            if (w == 0 || h == 0) return 0; /* minimized */
            reposition_controls(w, h);
            return 0;
        }

        case WM_GETMINMAXINFO: {
            MINMAXINFO *mmi = (MINMAXINFO *)lParam;
            mmi->ptMinTrackSize.x = 560;
            mmi->ptMinTrackSize.y = 400;
            return 0;
        }

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(245, 246, 247));
            SetTextColor(hdc, RGB(33, 33, 33));
            return (LRESULT)g_hbrBack;
        }

        case WM_CTLCOLOREDIT: {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(255, 255, 255));
            SetTextColor(hdc, RGB(33, 33, 33));
            return (LRESULT)g_hbrEdit;
        }

        case WM_CTLCOLORLISTBOX:
        case WM_CTLCOLORSCROLLBAR:
            return (LRESULT)g_hbrBack;

        case WM_NOTIFY: {
            LPNMHDR pnm = (LPNMHDR)lParam;
            if (pnm->idFrom == IDC_TAB && pnm->code == TCN_SELCHANGE) {
                int idx = TabCtrl_GetCurSel(g_hTab);
                show_tab(idx);
            }
            return 0;
        }

        case WM_COMMAND: {
            int id = LOWORD(wParam);
            if (id == IDC_BROWSE) {
                open_file();
            } else if (id == IDC_BTN_ASCII || id == IDC_BTN_UNICODE) {
                int min_len = DEFAULT_MIN_STRING_LEN;
                char txt[16] = {0};
                GetWindowTextA(g_hEditMinLen, txt, sizeof(txt));
                char *endptr = NULL;
                long val = strtol(txt, &endptr, 10);
                if (endptr != txt && val >= 1 && val <= 64) min_len = (int)val;

                char filter[256] = {0};
                GetWindowTextA(g_hEditStrFilter, filter, sizeof(filter));

                str_builder sb;
                sb_init(&sb);
                extract_strings(&sb, min_len, (id == IDC_BTN_UNICODE), filter);
                set_edit_text(g_hEditStrings, sb.buf ? sb.buf : "");
                sb_free(&sb);
            } else if (id == IDC_BTN_HEXDUMP) {
                char offTxt[32] = {0}, lenTxt[32] = {0};
                GetWindowTextA(g_hEditHexOffset, offTxt, sizeof(offTxt));
                GetWindowTextA(g_hEditHexLen, lenTxt, sizeof(lenTxt));
                char *endptr = NULL;
                size_t off = (size_t)strtoull(offTxt, &endptr, 0);
                if (endptr == offTxt) off = 0;
                size_t len = (size_t)strtoull(lenTxt, &endptr, 0);
                if (endptr == lenTxt || len == 0) len = DEFAULT_HEX_LEN;

                str_builder sb;
                sb_init(&sb);
                build_hex_dump(&sb, off, len);
                set_edit_text(g_hEditHex, sb.buf ? sb.buf : "");
                sb_free(&sb);
            } else if (id == IDC_BTN_SCAN_PATTERNS) {
                unsigned int mask = 0;
                for (int p = 0; p < (int)NUM_PATTERNS; ++p) {
                    if (g_hChkPatterns[p] && SendMessageA(g_hChkPatterns[p], BM_GETCHECK, 0, 0) == BST_CHECKED)
                        mask |= (1u << p);
                }
                str_builder sb;
                sb_init(&sb);
                scan_patterns(&sb, mask);
                set_edit_text(g_hEditPatterns, sb.buf ? sb.buf : "");
                sb_free(&sb);
            }
            return 0;
        }

        case WM_DESTROY:
            if (g_buf) { free(g_buf); g_buf = NULL; g_size = 0; }
            if (g_hbrBack) { DeleteObject(g_hbrBack); g_hbrBack = NULL; }
            if (g_hbrEdit) { DeleteObject(g_hbrEdit); g_hbrEdit = NULL; }
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;

    INITCOMMONCONTROLSEX icc = {0};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "PEAnyGUI";
    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    g_hMain = CreateWindowExA(0, "PEAnyGUI", "PE-Any",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 660, 470,
        NULL, NULL, hInstance, NULL);
    if (!g_hMain) {
        MessageBoxA(NULL, "Failed to create window.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hMain, nCmdShow);
    UpdateWindow(g_hMain);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
