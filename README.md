# ransomware_blog

For more information visit [here](www.berylliumsec.com/blog/https/wwwberylliumseccom/blog-page-url/new-post-title)

## Windows

### Requirements

- Clang
- Openssl

To compile, do 

```bash
clang-cl -I"C:\Program Files\OpenSSL-Win64\include" ransomware_windows_poc.c /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" ws2_32.lib libssl.lib libcrypto.lib
```

## Linux

### Requirements

- GCC
- Openssl

To compile, do 

```bash
gcc -O2 -maes -msse4.1 -fno-pie -no-pie     ransomware_windows_poc.c -o ransomware_windows_poc.c    -lssl -lcrypto -ldl -lpthread
```