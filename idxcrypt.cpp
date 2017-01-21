/*
 * A small utility to encrypt/decrypt files using AES256 and strong password key derivation.
 *
 * The AES256 key is derived from password using PBKDF2 with 500000 iterations.
 * 
 * All cryptographic operations are done using Windows Crypto API.
 *
 * Copyright (c) 2014-2016 Mounir IDRASSI <mounir.idrassi@idrix.fr>. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

#ifndef _WIN32_WINNT         
#define _WIN32_WINNT 0x0501 /* Windows XP minimum */
#endif

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x05010300 /* XP SP3 minimum */
#endif

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <io.h>
#include <math.h>
#include <time.h>
#include <tchar.h>

#ifndef MS_ENH_RSA_AES_PROV_XP
#define MS_ENH_RSA_AES_PROV_XP  L"Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
#endif

#define STRONG_ITERATIONS	500000

#define READ_BUFFER_SIZE	65536

// Pseudo Random Function (PRF) prototype

/* generic context used in HMAC calculation */

#define PRF_CTX_MAGIC 0x50524643

typedef struct
{
	DWORD	magic;			/* used to help check that we are using the correct context */
	DWORD digestSize;		/* digest size in bytes of the underlying hash algorithm */
	void*	pParam;	      /* hold a custom pointer known to the implementation  */
} PRF_CTX;

typedef BOOL (WINAPI* PRF_HmacInitPtr)(
	PRF_CTX*       pContext,   /* PRF context used in HMAC computation */
	unsigned char* pbKey,      /* pointer to authentication key */
	DWORD          cbKey       /* length of authentication key */                        
	);

typedef BOOL (WINAPI* PRF_HmacPtr)(
	PRF_CTX*       pContext,   /* PRF context initialized by HmacInit */
	unsigned char*  pbData,    /* pointer to data stream */
	DWORD          cbData,     /* length of data stream */                           
	unsigned char* pbDigest    /* caller digest to be filled in */                           
	);

typedef BOOL (WINAPI* PRF_HmacFreePtr)(
	PRF_CTX*       pContext	/* PRF context initialized by HmacInit */                        
	);


/* PRF type definition */
typedef struct
{
	PRF_HmacInitPtr   hmacInit;
	PRF_HmacPtr       hmac;
	PRF_HmacFreePtr	hmacFree;
} PRF;


/* Implementation of HMAC using CAPI */

typedef struct
{
	HCRYPTPROV hProv;
	HCRYPTHASH hInnerHash;
	HCRYPTHASH hOuterHash;
} CAPI_CTX_PARAM;

// Structure used by CAPI for HMAC computation
typedef struct {
	BLOBHEADER hdr;
	DWORD cbKeySize;
} HMAC_KEY_BLOB;

BOOL WINAPI hmacGenericInit(
	PRF_CTX*       pContext,   /* PRF context used in HMAC computation */
	ALG_ID			hashAlgid,	/* hash algorithm used in HMAC */
	unsigned char* pbKey,      /* pointer to authentication key */
	DWORD          cbKey       /* length of authentication key */                        
	)
{
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL, hInnerHash = NULL, hOuterHash = NULL;
	DWORD cbDigestSize, cbBlockSize;
	BOOL bStatus = FALSE;
	DWORD dwError = 0, i;
	BYTE key[64];
	BYTE buffer[128];

	switch (hashAlgid)
	{
		case CALG_SHA1: cbDigestSize = 20; cbBlockSize = 64; break;
		case CALG_SHA_256: cbDigestSize = 32;  cbBlockSize = 64; break;
		case CALG_SHA_384: cbDigestSize = 48;  cbBlockSize = 128; break;
		case CALG_SHA_512: cbDigestSize = 64;  cbBlockSize = 128; break;
		default: return FALSE;
	}

	if (!pContext)
	{
		dwError = ERROR_BAD_ARGUMENTS;
		goto hmacInit_end;
	}

   if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) 
   {
		if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			dwError = GetLastError();
			goto hmacInit_end;
		}
   }

	if (	!CryptCreateHash (hProv, hashAlgid, NULL, 0, &hHash) 
		|| !CryptCreateHash (hProv, hashAlgid, NULL, 0, &hInnerHash)
		|| !CryptCreateHash (hProv, hashAlgid, NULL, 0, &hOuterHash)
		)
	{
		dwError = GetLastError();
		goto hmacInit_end;
	}

	if (cbKey > cbBlockSize)
	{
		/* If key is larger than hash algorithm block size,
	    * set key = hash(key) as per HMAC specifications.
		 */
		if (!CryptHashData (hHash, pbKey, cbKey, 0))
		{
			dwError = GetLastError();
			goto hmacInit_end;
		}

		cbKey = sizeof (key);
		if (!CryptGetHashParam (hHash, HP_HASHVAL, key, &cbKey, 0))
		{
			dwError = GetLastError();
			goto hmacInit_end;
		}

		pbKey = key;
	}

	/* Precompute HMAC Inner Digest */

	for (i = 0; i < cbKey; ++i)
		buffer[i] = (char) (pbKey[i] ^ 0x36);
	memset (&buffer[cbKey], 0x36, cbBlockSize - cbKey);

	if (!CryptHashData (hInnerHash, buffer, cbBlockSize, 0))
	{
		dwError = GetLastError();
		goto hmacInit_end;
	}

	/* Precompute HMAC Outer Digest */

	for (i = 0; i < cbKey; ++i)
		buffer[i] = (char) (pbKey[i] ^ 0x5C);
	memset (&buffer[cbKey], 0x5C, cbBlockSize - cbKey);

	if (!CryptHashData (hOuterHash, buffer, cbBlockSize, 0))
	{
		dwError = GetLastError();
		goto hmacInit_end;
	}

	CAPI_CTX_PARAM* pParam = (CAPI_CTX_PARAM*) LocalAlloc(0, sizeof(CAPI_CTX_PARAM));
	pParam->hProv = hProv;
	pParam->hInnerHash = hInnerHash;
	pParam->hOuterHash = hOuterHash;

	pContext->magic = PRF_CTX_MAGIC;
	pContext->digestSize = cbDigestSize;
	pContext->pParam = (void*) pParam;

	hProv = NULL;
	hInnerHash = NULL;
	hOuterHash = NULL;

	bStatus = TRUE;

hmacInit_end:

	if (hHash) CryptDestroyHash(hHash);
	if (hInnerHash) CryptDestroyHash(hInnerHash);
	if (hOuterHash) CryptDestroyHash(hOuterHash);
	if (hProv) CryptReleaseContext(hProv, 0);

	SetLastError(dwError);
	return bStatus;
}

BOOL WINAPI hmacGeneric(
	PRF_CTX*       pContext,               /* PRF context used in HMAC computation */  
	unsigned char*  pbData,                /* pointer to data stream */
	DWORD           cbData,                /* length of data stream */
	unsigned char*  pbDigest					/* caller digest to be filled in */
)
{
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	HCRYPTHASH hInnerHash = NULL;
	HCRYPTHASH hOuterHash = NULL;
	DWORD cbDigest = 0;
	BOOL bStatus = FALSE;
	DWORD dwError = 0;

	if (!pContext || (pContext->magic != PRF_CTX_MAGIC) || (!pContext->pParam))
	{
		dwError = ERROR_BAD_ARGUMENTS;
		goto hmac_end;
	}

	hProv = ((CAPI_CTX_PARAM*) pContext->pParam)->hProv;
	hInnerHash = ((CAPI_CTX_PARAM*) pContext->pParam)->hInnerHash;
	hOuterHash = ((CAPI_CTX_PARAM*) pContext->pParam)->hOuterHash;	

	/* Restore Precomputed Inner Digest Context */

	if (!CryptDuplicateHash( hInnerHash, NULL, 0, &hHash))
	{
		dwError = GetLastError();
		goto hmac_end;
	}

	if (!CryptHashData(hHash, pbData, cbData, 0))
	{
		dwError = GetLastError();
		goto hmac_end;
	}

	cbDigest = pContext->digestSize;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, pbDigest, &cbDigest, 0))
	{
		dwError = GetLastError();
		goto hmac_end;
	}

	CryptDestroyHash(hHash);
	hHash = NULL;

	/* Restore Precomputed Outer Digest Context */

	if (!CryptDuplicateHash( hOuterHash, NULL, 0, &hHash))
	{
		dwError = GetLastError();
		goto hmac_end;
	}

	if (!CryptHashData(hHash, pbDigest, cbDigest, 0))
	{
		dwError = GetLastError();
		goto hmac_end;
	}

	cbDigest = pContext->digestSize;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, pbDigest, &cbDigest, 0))
	{
		dwError = GetLastError();
		goto hmac_end;
	}

	bStatus = TRUE;

hmac_end:

	if (hHash) CryptDestroyHash(hHash);

	SetLastError(dwError);
	return bStatus;
}


BOOL WINAPI hmacGenericFree(
	PRF_CTX*       pContext          /* PRF context used in HMAC computation */  
	)
{
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hInnerHash = NULL;
	HCRYPTHASH hOuterHash = NULL;

	if (!pContext || (pContext->magic != PRF_CTX_MAGIC) || (!pContext->pParam))
	{
		SetLastError(ERROR_BAD_ARGUMENTS);
		return FALSE;
	}

	hProv = ((CAPI_CTX_PARAM*) pContext->pParam)->hProv;
	hInnerHash = ((CAPI_CTX_PARAM*) pContext->pParam)->hInnerHash;
	hOuterHash = ((CAPI_CTX_PARAM*) pContext->pParam)->hOuterHash;

	CryptDestroyKey(hInnerHash);
	CryptDestroyKey(hOuterHash);
	CryptReleaseContext(hProv, 0);

	LocalFree(pContext->pParam);
	SecureZeroMemory(pContext, sizeof(PRF_CTX));

	return TRUE;
}

/*
 * Definition of the HMAC PRF objects
 */

static BOOL WINAPI hmacInit_sha1( PRF_CTX* pContext, unsigned char* pbKey, DWORD cbKey)
{
	return hmacGenericInit (pContext, CALG_SHA1, pbKey, cbKey);
}

static BOOL WINAPI hmacInit_sha256( PRF_CTX* pContext, unsigned char* pbKey, DWORD cbKey)
{
	return hmacGenericInit (pContext, CALG_SHA_256, pbKey, cbKey);
}

static BOOL WINAPI hmacInit_sha384( PRF_CTX* pContext, unsigned char* pbKey, DWORD cbKey)
{
	return hmacGenericInit (pContext, CALG_SHA_384, pbKey, cbKey);
}

static BOOL WINAPI hmacInit_sha512( PRF_CTX* pContext, unsigned char* pbKey, DWORD cbKey)
{
	return hmacGenericInit (pContext, CALG_SHA_512, pbKey, cbKey);
}

PRF sha1Prf		= {hmacInit_sha1,		hmacGeneric, hmacGenericFree};
PRF sha256Prf	= {hmacInit_sha256,	hmacGeneric, hmacGenericFree};
PRF sha384Prf	= {hmacInit_sha384,	hmacGeneric, hmacGenericFree};
PRF sha512Prf	= {hmacInit_sha512,	hmacGeneric, hmacGenericFree};


static inline void xor(LPBYTE ptr1, LPBYTE ptr2, DWORD dwLen)
{
	if (dwLen)
		while (dwLen--) *ptr1++ ^= *ptr2++;
}

/*
 * PBKDF2 implementation
 */
BOOL PBKDF2(PRF pPrf,
	unsigned char* pbPassword,
	DWORD cbPassword,
	unsigned char* pbSalt,
	DWORD cbSalt,
	DWORD dwIterationCount,
	unsigned char* pbDerivedKey,
	DWORD          cbDerivedKey)
{
	BOOL bStatus = FALSE;
	DWORD dwError = 0;
	DWORD l, r, i,j;
	DWORD hlen;
	LPBYTE Ti = NULL;
	LPBYTE V = NULL;
	LPBYTE U = NULL;
	DWORD dwULen;
	PRF_CTX prfCtx = {0};

	if (!pbDerivedKey || !cbDerivedKey || (!pbPassword && cbPassword) )
	{
		dwError = ERROR_BAD_ARGUMENTS;
		goto PBKDF2_end;
	}

	if (!pPrf.hmacInit(&prfCtx, pbPassword, cbPassword))
	{
		dwError = GetLastError();
		goto PBKDF2_end;
	}

	hlen = prfCtx.digestSize;

	Ti = (LPBYTE) LocalAlloc(0, hlen);
	V = (LPBYTE) LocalAlloc(0, hlen);
	U = (LPBYTE) LocalAlloc(0, max((cbSalt + 4), hlen));

	if (!Ti || !U || !V)
	{
		dwError = ERROR_NOT_ENOUGH_MEMORY;
		goto PBKDF2_end;
	}

	l = (DWORD) ceil((double) cbDerivedKey / (double) hlen);
	r = cbDerivedKey - (l - 1) * hlen;

	for (i = 1; i <= l; i++)
	{
		ZeroMemory(Ti, hlen);
		for (j = 0; j < dwIterationCount; j++)
		{
			if (j == 0)
			{
				// construct first input for PRF
				memcpy(U, pbSalt, cbSalt);
				U[cbSalt] = (BYTE) ((i & 0xFF000000) >> 24);
				U[cbSalt + 1] = (BYTE) ((i & 0x00FF0000) >> 16);
				U[cbSalt + 2] = (BYTE) ((i & 0x0000FF00) >> 8);
				U[cbSalt + 3] = (BYTE) ((i & 0x000000FF));
				dwULen = cbSalt + 4;
			}
			else
			{
				memcpy(U, V, hlen);
				dwULen = hlen;
			}

			if (!pPrf.hmac(&prfCtx, U, dwULen, V))
			{
				dwError = GetLastError();
				goto PBKDF2_end;
			}

			xor(Ti, V, hlen);
		}

		if (i != l)
		{
			memcpy(&pbDerivedKey[(i-1) * hlen], Ti, hlen);
		}
		else
		{
			// Take only the first r bytes
			memcpy(&pbDerivedKey[(i-1) * hlen], Ti, r);
		}
	}

	bStatus = TRUE;

PBKDF2_end:

	pPrf.hmacFree(&prfCtx);

	if (Ti) LocalFree(Ti);
	if (U) LocalFree(U);
	if (V) LocalFree(V);
	SetLastError(dwError);
	return bStatus;
}


BOOL GenerateRandom(LPBYTE pbRand, DWORD cbRand)
{
	HCRYPTPROV hProv;
	BOOL bRet = CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (bRet)
	{
		bRet = CryptGenRandom(hProv, cbRand, pbRand);
		CryptReleaseContext(hProv, 0);
	}
	
	return bRet;
}

BOOL ImportKeyData(HCRYPTPROV hProvider, ALG_ID Algid, BYTE *pbKeyData, DWORD cbKeyData, HCRYPTKEY* phKey)
{
	BOOL       bResult = FALSE;
	BYTE       *pbData = 0;
	DWORD      cbData, cbHeaderLen, cbKeyLen, dwDataLen;
	ALG_ID     *pAlgid;
	HCRYPTKEY  hImpKey = 0;
	BLOBHEADER *pBlob;

	if (!CryptGetUserKey(hProvider, AT_KEYEXCHANGE, &hImpKey)) {
		if (GetLastError(  ) != NTE_NO_KEY) goto done;
		if (!CryptGenKey(hProvider, AT_KEYEXCHANGE, (1024 << 16), &hImpKey))
			goto done;
	}

	cbData = cbKeyData;
	cbHeaderLen = sizeof(BLOBHEADER) + sizeof(ALG_ID);
	if (!CryptEncrypt(hImpKey, 0, TRUE, 0, 0, &cbData, cbData)) goto done;
	if (!(pbData = (BYTE *)LocalAlloc(LMEM_FIXED, cbData + cbHeaderLen)))
		goto done;
	CopyMemory(pbData + cbHeaderLen, pbKeyData, cbKeyData);
	cbKeyLen = cbKeyData;
	if (!CryptEncrypt(hImpKey, 0, TRUE, 0, pbData + cbHeaderLen, &cbKeyLen, cbData))
		goto done;

	pBlob  = (BLOBHEADER *)pbData;
	pAlgid = (ALG_ID *)(pbData + sizeof(BLOBHEADER));
	pBlob->bType    = SIMPLEBLOB;
	pBlob->bVersion = 2;
	pBlob->reserved = 0;
	pBlob->aiKeyAlg = Algid;
	dwDataLen = sizeof(ALG_ID);
	if (!CryptGetKeyParam(hImpKey, KP_ALGID, (BYTE *)pAlgid, &dwDataLen, 0))
		goto done;

	bResult = CryptImportKey(hProvider, pbData, cbData + cbHeaderLen, hImpKey, 0,
		phKey);
	if (bResult) SecureZeroMemory(pbKeyData, cbKeyData);

done:
	if (pbData) LocalFree(pbData);
	CryptDestroyKey(hImpKey);
	return bResult;
}


typedef struct
{
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	BOOL bForDecrypt;
} AES_CTX;

BOOL AesInit(LPBYTE pbKey, LPBYTE pbIV, BOOL bForDecrypt, AES_CTX* pCtx)
{
	BOOL bRet = CryptAcquireContext(&pCtx->hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	if (!bRet)
		bRet = CryptAcquireContext(&pCtx->hProv, NULL, MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	if (bRet)
	{
		bRet = ImportKeyData(pCtx->hProv, CALG_AES_256, pbKey, 32, &pCtx->hKey);
		if (bRet)
		{
			DWORD dwMode = CRYPT_MODE_CBC;
			bRet = CryptSetKeyParam(pCtx->hKey, KP_MODE, (BYTE *)&dwMode, 0);
			if (bRet)
				bRet = CryptSetKeyParam(pCtx->hKey, KP_IV, pbIV, 0);

			if (!bRet)
				CryptDestroyKey(pCtx->hKey);
		}

		if (!bRet)
			CryptReleaseContext(pCtx->hProv, 0);
	}

	pCtx->bForDecrypt = bForDecrypt;

	return bRet;
}

BOOL AesProcess(AES_CTX* pCtx, LPBYTE pbData, LPDWORD pcbData, DWORD cbBuffer, BOOL bFinal)
{
	BOOL bRet;
	if (pCtx->bForDecrypt)
		bRet = CryptDecrypt(pCtx->hKey, NULL, bFinal, 0, pbData, pcbData);
	else
		bRet = CryptEncrypt(pCtx->hKey, NULL, bFinal, 0, pbData, pcbData, cbBuffer);

	return bRet;
}

/* Function to display information about the progress of the current operation */
clock_t startClock = 0;
clock_t currentClock = 0;

void ShowProgress (LPCTSTR szOperationDesc, __int64 inputLength, __int64 totalProcessed, BOOL bFinalBlock)
{
	/* display progress information every 2 seconds */
	clock_t t = clock();
	if ((currentClock == 0) || bFinalBlock || ((t - currentClock) >= (2 * CLOCKS_PER_SEC)))
	{
		currentClock = t;
		if (currentClock == startClock) currentClock = startClock + 1;
		double processingTime = (double) (currentClock - startClock) / (double) CLOCKS_PER_SEC;
		if (bFinalBlock)
			_tprintf(_T("\r%sDone! (time: %.2fs - speed: %.2f MiB/s)\n"), szOperationDesc, processingTime, (double) totalProcessed / (processingTime * 1024.0 * 1024.0));
		else
			_tprintf(_T("\r%s (%.2f%% - %.2f MiB/s)"), szOperationDesc, ((double) totalProcessed * 100.0)/ (double) inputLength, (double) totalProcessed / (processingTime * 1024.0 * 1024.0));
	}
}

void ShowUsage()
{
   _tprintf(_T("Usage : idxcrypt InputFile Password OutputFile [/d] [/hash algo]\n"));
	_tprintf(_T("\tParameters:\n"));
	_tprintf(_T("\t  /d: Perform decryption instead of encryption\n"));
	_tprintf(_T("\t  /hash algo: Specified hash algorithm to use for key derivation.\n"));
	_tprintf(_T("\t              Possible value are sha256, sha384 and sha512.\n"));
	_tprintf(_T("\t              sha256 is the default\n"));
	_tprintf(_T("\n"));
}

int _tmain(int argc, TCHAR* argv[])
{  
	int iStatus = 0;
	BYTE pbDerivedKey[256];
	BYTE pbSalt[64], pbIV[16];
	FILE* fin = NULL;
	FILE* fout = NULL;
	int i, iLen;
	char szPassword[129]; // maximum 128 UTF8 bytes
	BYTE pbData[READ_BUFFER_SIZE + 32];
	DWORD cbData;
	__int64 inputLength, totalProcessed = 0;
	size_t readLen = 0;
	BOOL bForDecrypt = FALSE;
	PRF* pPrf = &sha256Prf; // PBKDF2-SHA256 is used by default
	size_t cbSalt = 16; // 16 bytes salt for SHA-256 and 64-bytes otherwise
	
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	_tprintf(_T("\nidxcrypt - Simple yet Strong file encryptor. By IDRASSI Mounir (mounir@idrix.fr)\n\nCopyright 2016 IDRIX\n\n\n"));

	if (argc < 4 || argc > 7)
	{
		ShowUsage ();
		iStatus = -1;
		goto main_end;
	}

	if (argc >= 5)
	{
      for (i = 4; i < argc; i++)
      {
         if (_tcsicmp(argv[i],_T("/hash")) == 0)
         {
            if ((i + 1) >= argc)
            {
               // missing file argument               
					ShowUsage ();
					iStatus = -1;
					goto main_end;
            }

            if (_tcsicmp(argv[i+1], _T("sha256")) == 0)
					pPrf = &sha256Prf;
				else if (_tcsicmp(argv[i+1], _T("sha384")) == 0)
				{
					pPrf = &sha384Prf;
					cbSalt = 64;
				}
				else if (_tcsicmp(argv[i+1], _T("sha512")) == 0)
				{
					pPrf = &sha512Prf;
					cbSalt = 64;
				}
				else
				{
               // missing file argument               
					ShowUsage ();
					iStatus = -1;
					goto main_end;
				}
            i++;
         }
         else if (_tcsicmp(argv[i],_T("/d")) == 0)
         {
            bForDecrypt = TRUE;
         }
         else
         {
				ShowUsage ();
				iStatus = -1;
				goto main_end;
         }
      }
	}



	fin = _tfopen(argv[1], _T("rb"));
	if (!fin)
	{
		_tprintf(_T("Failed to open the input file for reading\n"));
		iStatus = -1;
		goto main_end;
	}


	if ((inputLength = _filelengthi64(_fileno(fin))) == 0)
	{
		_tprintf(_T("The input file is empty. No action will be performed.\n"));
		iStatus = -1;
		goto main_end;
	}

	if (bForDecrypt && ((inputLength < (__int64) (48 + cbSalt)) || (inputLength % 16)))
	{
		_tprintf(_T("Error : input file is not a valid encrypted file.\n"));
		iStatus = -1;
		goto main_end;
	}

	fout = _tfopen(argv[3], _T("wb"));
	if (!fout)
	{
		_tprintf(_T("Failed to open the output file for writing\n"));
		iStatus = -1;
		goto main_end;
	}

	/* protect password memory against swaping */
	VirtualLock(szPassword, sizeof(szPassword));

	/* convert the password to UTF8 */
	iLen = WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, NULL, 0, NULL, NULL);
	if (iLen > sizeof(szPassword))
	{
		DWORD dwErr = GetLastError();
		_tprintf(_T("Password is too long. Maximum allowed length is %d\n"), (sizeof(szPassword) - 1));
		iStatus = -1;
		goto main_end;
	}

	if (!WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, szPassword, sizeof(szPassword), NULL, NULL))
	{
		DWORD dwErr = GetLastError();
		_tprintf(_T("An unexpected error occured while converting the password (Code 0x%.8X)\n"), dwErr);
		iStatus = -1;
		goto main_end;
	}

	/* clear the password in the command line */
	SecureZeroMemory(argv[2], _tcslen(argv[2]) * sizeof(TCHAR));	

	if (bForDecrypt)
	{
		if ((cbSalt != fread(pbSalt, 1, cbSalt, fin)) || (16 != fread(pbIV, 1, 16, fin)))
		{
			_tprintf(_T("An unexpected error occured while reading the input file\n"));
			iStatus = -1;
			goto main_end;
		}

		/* remove size of salt and IV from the input length */
		inputLength -= (__int64) (16 + cbSalt);
	}
	else
	{
		/* generate random salt */
		if (!GenerateRandom(pbSalt, (DWORD) cbSalt) || !GenerateRandom(pbIV, 16))
		{
			DWORD dwErr = GetLastError();
			_tprintf(_T("An unexpected error occured while preparing for the encryption (Code 0x%.8X)\n"), dwErr);
			iStatus = -1;
			goto main_end;
		}
	}

	if (bForDecrypt)
		_tprintf(_T("Generating the decryption key..."));
	else
		_tprintf(_T("Generating the encryption key..."));

   if (!PBKDF2(*pPrf, (LPBYTE) szPassword, (DWORD) strlen(szPassword), pbSalt, (DWORD) cbSalt, STRONG_ITERATIONS, pbDerivedKey, 32))
   {
		if (bForDecrypt)
			_tprintf(_T("Error!\nAn unexpected error occured while creating the decryption key (Code 0x%.8X)\n"), GetLastError());
		else
			_tprintf(_T("Error!\nAn unexpected error occured while creating the encryption key (Code 0x%.8X)\n"), GetLastError());
		iStatus = -1;
      goto main_end;
   }
	else
	{
		if (bForDecrypt)
			_tprintf(_T("Done!\nInitializing decryption..."));
		else
			_tprintf(_T("Done!\nInitializing encryption..."));
		AES_CTX ctx;
		BOOL bStatus;
		if (AesInit(pbDerivedKey, pbIV, bForDecrypt, &ctx))
		{
			TCHAR szOpDesc[64];
			BYTE pbHeader[16];
			memcpy(pbHeader, "IDXCRYPTTPYRCXDI", 16);

			_tprintf(_T("Done!\n"));

			if (bForDecrypt)
				_tcscpy(szOpDesc, _T("Decrypting the input file..."));
			else
				_tcscpy(szOpDesc, _T("Encrypting the input file..."));

			_tprintf(szOpDesc);

			if (bForDecrypt)
			{
				cbData = (DWORD) fread(pbData, 1, 16, fin);
				/* remove size of header from input length */
				inputLength -= 16;

				if (cbData == 16)
				{
					if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE))
					{
						if ((cbData == 16) && (0 == memcmp(pbData, pbHeader, 16)))
						{
							BOOL bFinal = FALSE;
							startClock = clock();
							while (!bFinal && ((readLen = fread(pbData, 1, READ_BUFFER_SIZE, fin)) == READ_BUFFER_SIZE))
							{
								cbData = (DWORD) readLen;
								totalProcessed += (__int64) READ_BUFFER_SIZE;
								bFinal = (totalProcessed == inputLength)? TRUE : FALSE;
								if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), bFinal))
								{
									if (cbData == fwrite(pbData,1,cbData,fout))
									{
										ShowProgress (szOpDesc, inputLength, totalProcessed, bFinal);
									}
									else
									{
										// Not all decrypted bytes writtent to disk. Aborting!
										iStatus = -2;
										break;
									}
								}
								else
								{
									iStatus = -3;
									break;
								}
							}

							if ((iStatus == 0) && !bFinal)
							{
								if (ferror (fin))
								{
									iStatus = -1;
								}
								else
								{
									cbData = (DWORD) readLen;
									totalProcessed += (__int64) readLen;
									if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), TRUE))
									{
										if (cbData == fwrite(pbData,1,cbData,fout))
										{
											ShowProgress (szOpDesc, inputLength, totalProcessed, TRUE);
										}
										else
										{
											// Not all encrypted bytes writtent to disk. Aborting!									
											iStatus = -2;
										}
									}
									else
										iStatus = -3;
								}
							}
						}
						else
						{
						
							iStatus = -4;
						}
					}
					else
					{
						iStatus = -3;
					}
				}
				else
				{
					iStatus = -1;
				}
			}
			else
			{
				/* write the random salt */
				fwrite(pbSalt,1,cbSalt,fout);

				/* write the random IV */
				fwrite(pbIV,1,16,fout);

				/* protect encryption memory against swaping */
				VirtualLock(pbData, sizeof(pbData));

				memcpy(pbData, pbHeader, 16);
				cbData = 16;

				if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE))
				{
					fwrite(pbData,1,cbData,fout);
					startClock = clock();
					while ((readLen = fread(pbData, 1, READ_BUFFER_SIZE, fin)) == READ_BUFFER_SIZE)
					{
						cbData = (DWORD) READ_BUFFER_SIZE;
						bStatus = AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE);
						if (bStatus)
						{
							totalProcessed += (__int64) READ_BUFFER_SIZE;
							if (cbData == fwrite(pbData,1,cbData,fout))
							{
								ShowProgress (szOpDesc, inputLength, totalProcessed, FALSE);
							}
							else
							{
								// Not all encrypted bytes writtent to disk. Aborting!
								iStatus = -2;
								break;
							}
						}
						else
						{
							iStatus = -3;
							break;
						}
					}

					if (iStatus == 0)
					{
						if (ferror (fin))
						{
							iStatus = -1;
						}
						else
						{
							cbData = (DWORD) readLen;
							if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), TRUE))
							{					
								totalProcessed += (__int64) readLen;
								if (cbData == fwrite(pbData,1,cbData,fout))
								{
									ShowProgress (szOpDesc, inputLength, totalProcessed, TRUE);
								}
								else
								{
									// Not all encrypted bytes writtent to disk. Aborting!
									iStatus = -2;
								}
							}
							else
								iStatus = -3;
						}
					}
				}
				else
					iStatus = -3;
			}

			if (iStatus == 0)
			{
				_tprintf(_T("Flushing output file data to disk, please wait..."));
				fclose(fout);
				fout = NULL;
				_tprintf(_T("\rInput file %s successfully as \"%s\"\n"), bForDecrypt? _T("decrypted") : _T("encrypted"), argv[3]);
			}
			else if (iStatus == -1)
			{
				_tprintf(_T("\nUnexpected error occured while reading data from input file. Aborting!\n"));
			}
			else if (iStatus == -2)
			{
				_tprintf(_T("\nUnexpected error occured while writing data to output file. Aborting!\n"));
			}
			else if (iStatus == -3)
			{
				_tprintf(_T("\nUnexpected error occured while %s data.\n"), szOpDesc, bForDecrypt? _T("decrypting") : _T("encrypting"));
			}
			else if (iStatus == -4)
			{
				_tprintf(_T("Error!\nPassword incorrect or the input file is not a valid encrypted file.\n"));
			}
			else
			{
				_tprintf(_T("\nUnknown error occured while %s input file.\n"), szOpDesc, bForDecrypt? _T("decrypting") : _T("encrypting"));
			}

		}
		else
		{
			_tprintf(_T("Error!\n"));
			iStatus = -1;
			goto main_end;
		}
	}

main_end:
	SecureZeroMemory(szPassword, sizeof(szPassword));
	if (fin) fclose(fin);
	if (fout)
	{
		fclose(fout);
		/* delete the file in case of error*/
		if (iStatus != 0) DeleteFile(argv[3]);
	}

	return iStatus;
}
