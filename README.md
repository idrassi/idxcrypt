# idxcrypt
Small Windows utility for strong file encryption based on AES256 and PBKDF2-SHA256

The AES256 key is derived from password using PBKDF2-SHA256 with 500000 iterations.
CBC mode is used for AES with a randomly generated IV that is unique to each file.
For PBKDF2, a random 16 bytes salt is generated for each file to protect again Rainbow-table attacks.

All cryptographic operations are done using Windows Crypto API so that the resulting executable file is small and depends only on Windows system dlls Kernel32.dll and Advapi32.dll.

Usage : idxcrypt InputFile Password OutputFile [/d]

If /d is omitted, then an encryption is performed.
If /d is specified, then a decryption is performed.

The password can contain Unicode non-ASCII characters.
