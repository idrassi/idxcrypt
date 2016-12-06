# idxcrypt
Small Windows utility for strong file encryption based on AES256 and PBKDF2-SHA256

The AES256 key is derived from password using PBKDF2-SHA256 with 500000 iterations.
All cryptographic operations are done using Windows Crypto API so that the resulting executable file is small and depends only on Windows system dlls Kernel32.dll and Advapi32.dll.
