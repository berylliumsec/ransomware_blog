/*
 * aes256_gcm_win_noimports_gcc.c
 *
 * A demonstration of "noimports" AES-256-GCM on Windows x86_64 using GCC-style inline assembly,
 * suitable for cross-compiling with x86_64-w64-mingw32-gcc on Linux.
 *
 * COMPILATION (example):
 *   x86_64-w64-mingw32-gcc \
 *       -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables \
 *       -fshort-wchar \
 *       -o aes256_gcm_win_noimports.exe aes256_gcm_win_noimports_gcc.c \
 *       -Wl,-entry,MyEntry -Wl,-subsystem,console
 *
 * NOTE:
 *   - We include <stddef.h> so that 'wchar_t' is recognized, and
 *     '-fshort-wchar' so it's 2 bytes (like Windows expects).
 *   - You may need to adjust NT syscall numbers for your OS version.
 *   - This is purely a demonstration with minimal error checks.
 */

#ifdef __GNUC__
#include <stddef.h>  // ensures 'wchar_t' is recognized in C
#endif

// If you still get complaints about wchar_t, you can also do:
//   #include <wchar.h>
// or
//   typedef unsigned short wchar_t;

// The rest of the code is the same as before, but with the crucial
// include above so that 'wchar_t' is known and recognized by GCC.

typedef unsigned long       ULONG;
typedef long                NTSTATUS;
typedef void*               HANDLE;
typedef long long           LONGLONG;
typedef unsigned long long  ULONGLONG;
typedef unsigned long long  UINT64;
typedef unsigned int        UINT32;

#define STATUS_SUCCESS      0
#define FILE_OPEN           0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_SUPERSEDE      0x00000000
#define FILE_OVERWRITE_IF   0x00000005

// Example syscalls (may differ on your Windows version)
#define SYSCALL_NtClose               0x18
#define SYSCALL_NtWriteFile           0x3D
#define SYSCALL_NtReadFile            0x3E
#define SYSCALL_NtOpenFile            0x55
#define SYSCALL_NtQueryDirectoryFile  0x58
#define SYSCALL_NtTerminateProcess    0x2E

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        void* Pointer;
    };
    ULONGLONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    void*           SecurityDescriptor;
    void*           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

static inline void InitializeObjectAttributes(
    OBJECT_ATTRIBUTES* p,
    UNICODE_STRING* n,
    ULONG attr,
    HANDLE r,
    void* sd
) {
    p->Length = sizeof(*p);
    p->RootDirectory = r;
    p->Attributes = attr;
    p->ObjectName = n;
    p->SecurityDescriptor = sd;
    p->SecurityQualityOfService = 0;
}

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LONGLONG CreationTime;
    LONGLONG LastAccessTime;
    LONGLONG LastWriteTime;
    LONGLONG ChangeTime;
    LONGLONG EndOfFile;
    LONGLONG AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    wchar_t FileName[1]; // variable-length
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

///////////////////////////////////////////////
// NT syscall stubs in GCC Intel syntax
///////////////////////////////////////////////

static NTSTATUS NtClose(HANDLE Handle)
{
    NTSTATUS ret;
    __asm__ volatile (
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx        \n\t"  // rcx has 'Handle'
        "mov eax, %1         \n\t"  // SYSCALL_NtClose
        "syscall             \n\t"
        "mov %0, eax         \n\t"  // store return in 'ret'
        ".att_syntax prefix\n\t"
        : "=r"(ret)
        : "i"(SYSCALL_NtClose), "c"(Handle)
        : "rax","r10","memory","cc"
    );
    return ret;
}

typedef struct {
    void*  Event;
    void*  Reserved;
} IO_APC, *PIO_APC;

static NTSTATUS NtReadFile(
    HANDLE FileHandle,
    void*  Event,
    void*  ApcRoutine,
    void*  ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock,
    void*  Buffer,
    ULONG  Length,
    LONGLONG* ByteOffset,
    ULONG* Key
)
{
    NTSTATUS ret;
    // NOTE: For 5+ params, Windows x64 calling convention places them on the stack.
    // This minimal code does not strictly ensure correct ordering beyond 4 registers. 
    // It's for demonstration only.
    __asm__ volatile(
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, %1\n\t"
        "syscall\n\t"
        "mov %0, eax\n\t"
        ".att_syntax prefix\n\t"
        : "=r"(ret)
        : "i"(SYSCALL_NtReadFile), "c"(FileHandle),
          "d"(Event), "b"(ApcRoutine), "D"(ApcContext),
          "S"(IoStatusBlock),
          "r"(Buffer), "r"(Length), "r"(ByteOffset), "r"(Key)
        : "rax","r10","memory","cc"
    );
    return ret;
}

static NTSTATUS NtWriteFile(
    HANDLE FileHandle,
    void*  Event,
    void*  ApcRoutine,
    void*  ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock,
    void*  Buffer,
    ULONG  Length,
    LONGLONG* ByteOffset,
    ULONG* Key
)
{
    NTSTATUS ret;
    __asm__ volatile(
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, %1\n\t"
        "syscall\n\t"
        "mov %0, eax\n\t"
        ".att_syntax prefix\n\t"
        : "=r"(ret)
        : "i"(SYSCALL_NtWriteFile), "c"(FileHandle),
          "d"(Event), "b"(ApcRoutine), "D"(ApcContext),
          "S"(IoStatusBlock),
          "r"(Buffer), "r"(Length), "r"(ByteOffset), "r"(Key)
        : "rax","r10","memory","cc"
    );
    return ret;
}

static NTSTATUS NtOpenFile(
    HANDLE* FileHandle,
    ULONG   DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    IO_STATUS_BLOCK* IoStatusBlock,
    ULONG   ShareAccess,
    ULONG   OpenOptions
)
{
    NTSTATUS ret;
    __asm__ volatile(
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, %1\n\t"
        "syscall\n\t"
        "mov %0, eax\n\t"
        ".att_syntax prefix\n\t"
        : "=r"(ret)
        : "i"(SYSCALL_NtOpenFile), "c"(FileHandle),
          "d"(DesiredAccess), "b"(ObjectAttributes),
          "D"(IoStatusBlock), "S"(ShareAccess)
          // The 6th param (OpenOptions) also goes on the stack, not shown here
        : "rax","r10","memory","cc"
    );
    (void)OpenOptions; // Not passed properly, demonstration only
    return ret;
}

static NTSTATUS NtQueryDirectoryFile(
    HANDLE FileHandle,
    void*  Event,
    void*  ApcRoutine,
    void*  ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock,
    void*  FileInformation,
    ULONG  Length,
    int    FileInformationClass,
    unsigned char ReturnSingleEntry,
    void*  FileName,
    unsigned char RestartScan
)
{
    NTSTATUS ret;
    __asm__ volatile(
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, %1\n\t"
        "syscall\n\t"
        "mov %0, eax\n\t"
        ".att_syntax prefix\n\t"
        : "=r"(ret)
        : "i"(SYSCALL_NtQueryDirectoryFile), "c"(FileHandle),
          "d"(Event), "b"(ApcRoutine), "D"(ApcContext),
          "S"(IoStatusBlock),
          "r"(FileInformation), "r"(Length), "r"(FileInformationClass),
          "r"(ReturnSingleEntry), "r"(FileName), "r"(RestartScan)
        : "rax","r10","memory","cc"
    );
    return ret;
}

static NTSTATUS NtTerminateProcess(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
)
{
    NTSTATUS ret;
    __asm__ volatile(
        ".intel_syntax noprefix\n\t"
        "mov r10, rcx\n\t"
        "mov eax, %1\n\t"
        "syscall\n\t"
        "mov %0, eax\n\t"
        ".att_syntax prefix\n\t"
        : "=r"(ret)
        : "i"(SYSCALL_NtTerminateProcess), "c"(ProcessHandle), "d"(ExitStatus)
        : "rax","r10","memory","cc"
    );
    return ret;
}

static void do_exit(NTSTATUS status)
{
    NtTerminateProcess((HANDLE)(-1), status);
    for(;;); 
}

////////////////////////////////////////////////////////////
// RDRAND for random IV (GCC Intel syntax)
////////////////////////////////////////////////////////////

static int rdrand_16bytes(unsigned char out[16])
{
    unsigned long long v1=0, v2=0;
    // first 8 bytes
    __asm__ volatile(
        ".intel_syntax noprefix\n\t"
        "1:\n\t"
        "rdrand rax\n\t"
        "jnc 1b\n\t"
        "mov %0, rax\n\t"
        ".att_syntax prefix\n\t"
        : "=r"(v1)
        :
        : "rax","cc"
    );
    // second 8 bytes
    __asm__ volatile(
        ".intel_syntax noprefix\n\t"
        "2:\n\t"
        "rdrand rax\n\t"
        "jnc 2b\n\t"
        "mov %0, rax\n\t"
        ".att_syntax prefix\n\t"
        : "=r"(v2)
        :
        : "rax","cc"
    );
    *(unsigned long long*)(&out[0]) = v1;
    *(unsigned long long*)(&out[8]) = v2;
    return 1;
}

////////////////////////////////////////////////////////////
// AES-256 KeySchedule + AES-NI block encryption
////////////////////////////////////////////////////////////

static const unsigned char sbox[256] = {
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

static const unsigned int Rcon[15] = {
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

static inline unsigned int RotWord(unsigned int w)
{
    return ((w << 8) & 0xFFFFFFFF) | (w >> 24);
}

static inline unsigned int SubWord(unsigned int w)
{
    return
        ((unsigned int)sbox[(w >> 24) & 0xFF] << 24) |
        ((unsigned int)sbox[(w >> 16) & 0xFF] << 16) |
        ((unsigned int)sbox[(w >>  8) & 0xFF] <<  8) |
        ((unsigned int)sbox[(w      ) & 0xFF]);
}

static void AES256_KeyExpansion(
    const unsigned char *key,
    unsigned char roundKeys[15][16])
{
    unsigned int W[60];
    for (int i = 0; i < 8; i++) {
        W[i] = ((unsigned int)key[4*i  ] << 24) |
               ((unsigned int)key[4*i+1] << 16) |
               ((unsigned int)key[4*i+2] <<  8) |
               ((unsigned int)key[4*i+3]);
    }
    for (int i = 8; i < 60; i++) {
        unsigned int temp = W[i - 1];
        if ((i % 8) == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i/8];
        } else if ((i % 8) == 4) {
            temp = SubWord(temp);
        }
        W[i] = W[i - 8] ^ temp;
    }
    for (int round = 0; round < 15; round++) {
        for (int j = 0; j < 4; j++) {
            unsigned int t = W[round*4 + j];
            roundKeys[round][4*j + 0] = (unsigned char)(t >> 24);
            roundKeys[round][4*j + 1] = (unsigned char)(t >> 16);
            roundKeys[round][4*j + 2] = (unsigned char)(t >>  8);
            roundKeys[round][4*j + 3] = (unsigned char)(t      );
        }
    }
}

static void AES256_EncryptBlock_InlineAsm(
    unsigned char block[16],
    const unsigned char roundKeys[15][16])
{
    __asm__ volatile (
        ".intel_syntax noprefix\n\t"
        // rcx => block, rdx => roundKeys
        "movdqu xmm0, [rcx]\n\t"
        "movdqu xmm1, [rdx]\n\t"
        "pxor xmm0, xmm1\n\t"

        "movdqu xmm1, [rdx+16]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+32]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+48]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+64]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+80]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+96]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+112]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+128]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+144]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+160]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+176]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+192]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+208]\n\t"
        "aesenc xmm0, xmm1\n\t"
        "movdqu xmm1, [rdx+224]\n\t"
        "aesenclast xmm0, xmm1\n\t"

        "movdqu [rcx], xmm0\n\t"
        ".att_syntax prefix\n\t"
        :
        : "c"(block), "d"(roundKeys)
        : "xmm0","xmm1","memory","cc"
    );
}

////////////////////////////////////////////////////////////
// Minimal GHASH + GCM encryption
////////////////////////////////////////////////////////////

static inline void xor_block(unsigned char *dst, const unsigned char *src)
{
    for (int i = 0; i < 16; i++) {
        dst[i] ^= src[i];
    }
}

static void gf_mul_128(const unsigned char *X, const unsigned char *Y, unsigned char *result)
{
    unsigned char Z[16];
    unsigned char V[16];
    for (int i = 0; i < 16; i++) {
        Z[i] = 0;
        V[i] = X[i];
    }
    for (int i = 0; i < 128; i++) {
        int bit_index = i >> 3;
        int shift = 7 - (i & 7);
        unsigned char mask = (unsigned char)(1 << shift);
        if (Y[bit_index] & mask) {
            xor_block(Z, V);
        }
        // shift V
        unsigned char carry = (V[0] & 0x80)?1:0;
        for(int b=0;b<15;b++){
            V[b] = (unsigned char)((V[b]<<1)|(V[b+1]>>7));
        }
        V[15]<<=1;
        if(carry){
            V[15]^=0x87;
        }
    }
    for (int i = 0; i < 16; i++) {
        result[i] = Z[i];
    }
}

static void ghash_update(
    unsigned char ghash_accum[16],
    const unsigned char H[16],
    const unsigned char block[16])
{
    unsigned char tmp[16];
    for (int i=0;i<16;i++){
        tmp[i] = ghash_accum[i]^block[i];
    }
    gf_mul_128(tmp,H,ghash_accum);
}

static void AES256_GCM_Encrypt(
    unsigned char *buf,
    long length,
    const unsigned char roundKeys[15][16],
    unsigned char J0[16],
    const unsigned char H[16],
    unsigned char ghash_accum[16]
)
{
    unsigned char ctr_block[16];
    long processed=0;
    while(processed<length){
        for(int i=0;i<16;i++){
            ctr_block[i]=J0[i];
        }
        AES256_EncryptBlock_InlineAsm(ctr_block,roundKeys);
        long block_len = (length-processed<16)?(length-processed):16;
        for(int i=0;i<block_len;i++){
            buf[processed+i]^=ctr_block[i];
        }
        // GHASH
        unsigned char tempBlock[16];
        for(int i=0;i<16;i++){
            tempBlock[i]=(i<block_len)?buf[processed+i]:0;
        }
        ghash_update(ghash_accum,H,tempBlock);

        // increment J0
        J0[15]++;
        if(J0[15]==0){
            J0[14]++;
            if(J0[14]==0){
                J0[13]++;
                if(J0[13]==0){
                    J0[12]++;
                }
            }
        }
        processed+=block_len;
    }
}

static void AES256_GCM_FinalizeTag(
    long length,
    const unsigned char roundKeys[15][16],
    const unsigned char H[16],
    unsigned char J0_initial[16],
    unsigned char ghash_accum[16],
    unsigned char outTag[16]
)
{
    unsigned char length_block[16];
    for(int i=0;i<16;i++) length_block[i]=0;
    unsigned long long cipherBits=(unsigned long long)length*8ULL;
    length_block[8]=(unsigned char)(cipherBits>>56);
    length_block[9]=(unsigned char)(cipherBits>>48);
    length_block[10]=(unsigned char)(cipherBits>>40);
    length_block[11]=(unsigned char)(cipherBits>>32);
    length_block[12]=(unsigned char)(cipherBits>>24);
    length_block[13]=(unsigned char)(cipherBits>>16);
    length_block[14]=(unsigned char)(cipherBits>>8);
    length_block[15]=(unsigned char)(cipherBits);

    ghash_update(ghash_accum,H,length_block);

    unsigned char S[16];
    for(int i=0;i<16;i++){
        S[i]=J0_initial[i];
    }
    AES256_EncryptBlock_InlineAsm(S,roundKeys);
    for(int i=0;i<16;i++){
        outTag[i]=S[i]^ghash_accum[i];
    }
}

////////////////////////////////////////////////////////////
// encrypt_file_gcm + directory
////////////////////////////////////////////////////////////

static void encrypt_file_gcm(
    const wchar_t* inPath,
    const wchar_t* outPath,
    const unsigned char roundKeys[15][16])
{
    // open inPath
    UNICODE_STRING usIn;
    usIn.Buffer=(wchar_t*)inPath;
    unsigned short inLen=0; while(inPath[inLen]) inLen++;
    usIn.Length = inLen*2;
    usIn.MaximumLength = usIn.Length;
    OBJECT_ATTRIBUTES oaIn;
    InitializeObjectAttributes(&oaIn,&usIn,0,0,0);

    IO_STATUS_BLOCK iosbIn;
    HANDLE hIn=0;
    NtOpenFile(&hIn,0x80000000,&oaIn,&iosbIn,1,
               FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);
    if(!hIn) return;

    // open outPath
    UNICODE_STRING usOut;
    usOut.Buffer=(wchar_t*)outPath;
    unsigned short outLen=0; while(outPath[outLen]) outLen++;
    usOut.Length=outLen*2;
    usOut.MaximumLength=usOut.Length;
    OBJECT_ATTRIBUTES oaOut;
    InitializeObjectAttributes(&oaOut,&usOut,0,0,0);

    IO_STATUS_BLOCK iosbOut;
    HANDLE hOut=0;
    NtOpenFile(&hOut,0x40000000,&oaOut,&iosbOut,0,
               FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_SUPERSEDE);
    if(!hOut){
        NtClose(hIn);
        return;
    }

    // GCM
    unsigned char J0[16]; for(int i=0;i<16;i++) J0[i]=0;
    rdrand_16bytes(J0); // fill 16 random
    // set last 4 bytes => 1
    J0[12]=0; J0[13]=0; J0[14]=0; J0[15]=1;
    unsigned char iv12[12];
    for(int i=0;i<12;i++){
        iv12[i]=J0[i];
    }
    IO_STATUS_BLOCK dummy;
    NtWriteFile(hOut,0,0,0,&dummy,iv12,12,0,0);

    unsigned char J0_initial[16];
    for(int i=0;i<16;i++){
        J0_initial[i]=J0[i];
    }
    // H => AES-enc(0^128)
    unsigned char H[16]; for(int i=0;i<16;i++) H[i]=0;
    AES256_EncryptBlock_InlineAsm(H,roundKeys);

    unsigned char ghash_accum[16];
    for(int i=0;i<16;i++) ghash_accum[i]=0;

    unsigned char buf[4096];
    long total=0;
    for(;;){
        iosbIn.Information=0;
        NTSTATUS st=NtReadFile(hIn,0,0,0,&iosbIn,buf,4096,0,0);
        if(iosbIn.Information==0) break;
        AES256_GCM_Encrypt(buf,(long)iosbIn.Information,
                           roundKeys,J0,H,ghash_accum);
        NtWriteFile(hOut,0,0,0,&dummy,buf,(ULONG)iosbIn.Information,0,0);
        total+=(long)iosbIn.Information;
        if(st!=0 && st!=0x80000005) break;
        if(st==0x80000005) break; // EOF
    }

    unsigned char tag[16];
    AES256_GCM_FinalizeTag(total,roundKeys,H,J0_initial,ghash_accum,tag);
    NtWriteFile(hOut,0,0,0,&dummy,tag,16,0,0);

    NtClose(hIn);
    NtClose(hOut);
}

static void encrypt_directory_gcm(
    const wchar_t* inDir,
    const wchar_t* outDir,
    const unsigned char roundKeys[15][16])
{
    UNICODE_STRING usIn;
    usIn.Buffer=(wchar_t*)inDir;
    unsigned short inLen=0; while(inDir[inLen]) inLen++;
    usIn.Length=inLen*2;
    usIn.MaximumLength=usIn.Length;
    OBJECT_ATTRIBUTES oaIn;
    InitializeObjectAttributes(&oaIn,&usIn,0,0,0);

    IO_STATUS_BLOCK iosb;
    HANDLE hDir=0;
    NtOpenFile(&hDir,0x80000000,&oaIn,&iosb,1,
               FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);
    if(!hDir) return;

    unsigned char dirbuf[8192];
    int restart=1;
    for(;;){
        iosb.Information=0;
        NTSTATUS st=NtQueryDirectoryFile(
            hDir,0,0,0,&iosb,
            dirbuf,sizeof(dirbuf),
            1,0,0,restart
        );
        if(st!=0) break;
        restart=0;
        unsigned long offset=0;
        while(1){
            FILE_DIRECTORY_INFORMATION* fdi=(FILE_DIRECTORY_INFORMATION*)(dirbuf+offset);
            if(fdi->FileNameLength>0){
                // check if directory
                if((fdi->FileAttributes & FILE_DIRECTORY_FILE)==0){
                    // file
                    wchar_t inPathFull[512];
                    wchar_t outPathFull[512];
                    int idx=0;
                    for(int i=0;i<inLen;i++){
                        inPathFull[idx++]=inDir[i];
                    }
                    if(idx>0 && inPathFull[idx-1]!=L'\\'){
                        inPathFull[idx++]=L'\\';
                    }
                    int fnameCount=(int)(fdi->FileNameLength/2);
                    for(int i=0;i<fnameCount;i++){
                        inPathFull[idx++]=fdi->FileName[i];
                    }
                    inPathFull[idx]=0;

                    int idx2=0;
                    unsigned short outLen2=0; while(outDir[outLen2]) outLen2++;
                    for(int i=0;i<outLen2;i++){
                        outPathFull[idx2++]=outDir[i];
                    }
                    if(idx2>0 && outPathFull[idx2-1]!=L'\\'){
                        outPathFull[idx2++]=L'\\';
                    }
                    for(int i=0;i<fnameCount;i++){
                        outPathFull[idx2++]=fdi->FileName[i];
                    }
                    outPathFull[idx2]=0;

                    encrypt_file_gcm(inPathFull,outPathFull,roundKeys);
                }
            }
            if(fdi->NextEntryOffset==0) break;
            offset+=fdi->NextEntryOffset;
        }
    }
    NtClose(hDir);
}

////////////////////////////////////////////////////////////
// "main": Minimal command-line parse + entry
////////////////////////////////////////////////////////////

static wchar_t globalCmdLine[1024] =
    L"program.exe keyfile.bin C:\\input_dir C:\\output_dir";

static wchar_t arg1[512], arg2[512], arg3[512];
static unsigned char g_key[32];
static unsigned char g_roundKeys[15][16];

static void parse_cmdline()
{
    int pos=0, token=0, idx=0;
    while(globalCmdLine[pos] && token<4){
        while(globalCmdLine[pos]==L' ' || globalCmdLine[pos]==L'\t')
            pos++;
        if(!globalCmdLine[pos]) break;
        if(token==0){
            // skip exe name
            while(globalCmdLine[pos] && globalCmdLine[pos]!=L' ' && globalCmdLine[pos]!=L'\t')
                pos++;
            token++;
        } else if(token==1){
            idx=0;
            while(globalCmdLine[pos] && globalCmdLine[pos]!=L' ' && globalCmdLine[pos]!=L'\t')
                arg1[idx++]=globalCmdLine[pos++];
            arg1[idx]=0; token++;
        } else if(token==2){
            idx=0;
            while(globalCmdLine[pos] && globalCmdLine[pos]!=L' ' && globalCmdLine[pos]!=L'\t')
                arg2[idx++]=globalCmdLine[pos++];
            arg2[idx]=0; token++;
        } else if(token==3){
            idx=0;
            while(globalCmdLine[pos] && globalCmdLine[pos]!=L' ' && globalCmdLine[pos]!=L'\t')
                arg3[idx++]=globalCmdLine[pos++];
            arg3[idx]=0; token++;
        }
    }
}

__attribute__((noreturn))
void MyEntry(void)
{
    parse_cmdline();
    if(!arg1[0] || !arg2[0] || !arg3[0]){
        do_exit(1);
    }

    // read keyfile
    {
        UNICODE_STRING usK;
        usK.Buffer=arg1;
        unsigned short klen=0; while(arg1[klen]) klen++;
        usK.Length=klen*2;
        usK.MaximumLength=usK.Length;

        OBJECT_ATTRIBUTES oaK;
        InitializeObjectAttributes(&oaK,&usK,0,0,0);
        IO_STATUS_BLOCK iosbK;
        HANDLE hK=0;
        NtOpenFile(&hK,0x80000000,&oaK,&iosbK,1,
                   FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);
        if(!hK) do_exit(2);

        iosbK.Information=0;
        NtReadFile(hK,0,0,0,&iosbK,g_key,32,0,0);
        NtClose(hK);
        if(iosbK.Information<32) do_exit(3);
    }

    AES256_KeyExpansion(g_key,g_roundKeys);

    encrypt_directory_gcm(arg2,arg3,g_roundKeys);

    do_exit(0);
}
