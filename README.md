# ransomware_blog

![pluto](/Images/ransom.png)

# Acknowledgement

First i would like to thank the All-Mighty God who is the source of all knowledge, without Him, this would not be possible.


For more information about this repository visit [here](www.berylliumsec.com/blog/https/wwwberylliumseccom/blog-page-url/new-post-title)

## Windows

### Requirements

- Clang
- Openssl

To compile, do: (change it to whatever matches your environment)

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

To start the server do

```bash
python server.py \
    --tls-port 9999 \
    --tcp-port 8080 \
    --key "ThisIsA32ByteKeyForExample01234567" \
    --cert cert.crt \
    --cert-key cert.key \
    --out-file uploaded_file.bin
```