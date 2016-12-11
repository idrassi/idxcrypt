# idxcrypt
Small Windows utility for strong file encryption based on AES256 and strong PBKDF2 key derivation.

The AES256 key is derived from password using PBKDF2 with 500000 iterations.
PBKDF2 supports SHA-256, SHA-384, SHA-512. SHA-256 is the default.
CBC mode is used for AES with a randomly generated IV that is unique to each file.
For PBKDF2, a random salt is generated for each file to protect again Rainbow-table attacks. It has a size of 16 bytes when SHA-256 is used and a size of 64 bytes otherwise.

All cryptographic operations are done using Windows Crypto API so that the resulting executable file is small and depends only on Windows system dlls Kernel32.dll and Advapi32.dll.

Usage : idxcrypt InputFile Password OutputFile [/d] [/hash algo]

If /d is omitted, then an encryption is performed.
If /d is specified, then a decryption is performed.

If /hash is ommited, the SHA-256 is used by PBKDF2.
if /hash is specified, then the hash algorithm indicated by algo parameter is used.
Possible values for algo are: sha256, sha384 and sha512.

The password can contain Unicode non-ASCII characters.
