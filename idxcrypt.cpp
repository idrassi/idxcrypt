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
#include <string.h>
#include <iostream>
#include <string>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

using namespace std;

#define MAX 32767

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

PRF sha1Prf		= {hmacInit_sha1,	hmacGeneric, hmacGenericFree};
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
	_tprintf(_T("Usage to encrypt an entire folder : idxcrypt InputFolder Password OutputFolder [/d] [/hash algo]\n"));
	_tprintf(_T("\tInputFolder example : C:\\inputFolder (absolute path) or inputFolder (relative path) \n"));
	_tprintf(_T("\tOutputFolder example : C:\\outputFolder (absolute path) or outputFolder (relative path) \n\n"));
	_tprintf(_T("Usage to encrypt a file : idxcrypt InputFile Password OutputFile [/d] [/hash algo]\n"));
	_tprintf(_T("\tInputFile example : C:\\inputFile (absolute path) or inputFile (relative path) \n"));
	_tprintf(_T("\tOutputFile example : C:\\outputFile (absolute path) or outputFile (relative path)\n"));
	_tprintf(_T("\tParameters:\n"));
	_tprintf(_T("\t  /d: Perform decryption instead of encryption\n"));
	_tprintf(_T("\t  /hash algo: Specified hash algorithm to use for key derivation.\n"));
	_tprintf(_T("\t              Possible value are sha256, sha384 and sha512.\n"));
	_tprintf(_T("\t              sha256 is the default\n"));
	_tprintf(_T("\n"));
	_tprintf(_T("\nPlease use backslashes rather than slashes!\n"));
}

int opFile(FILE* fin, FILE* fout, const WCHAR foutPath[], char szPassword[], BOOL bForDecrypt, PRF* pPrf, size_t cbSalt)
{
	BYTE pbDerivedKey[256];
	BYTE pbSalt[64], pbIV[16];
	BYTE pbData[READ_BUFFER_SIZE + 32];
	DWORD cbData;
	size_t readLen = 0;
	__int64 totalProcessed = 0;
	__int64 inputLength;
	int iStatus = 0;

	inputLength = _filelengthi64(_fileno(fin));

	if (bForDecrypt){
		if ((cbSalt != fread(pbSalt, 1, cbSalt, fin)) || (16 != fread(pbIV, 1, 16, fin)))
		{
			_tprintf(_T("An unexpected error occured while reading the input file. Aborting...\n"));
			iStatus = -1;
			return iStatus;
		}

		/* remove size of salt and IV from the input length */
		inputLength -= (__int64)(16 + cbSalt);
	}
	else
	{
		/* generate random salt and IV*/
		if (!GenerateRandom(pbSalt, (DWORD)cbSalt) || !GenerateRandom(pbIV, 16))
		{
			DWORD dwErr = GetLastError();
			_tprintf(_T("An unexpected error occured while preparing for the encryption (Code 0x%.8X). Aborting...\n"), dwErr);
			iStatus = -1;
			return iStatus;
		}
	}

	if (bForDecrypt)
		_tprintf(_T("Generating the decryption key..."));
	else
		_tprintf(_T("Generating the encryption key..."));

	if (!PBKDF2(*pPrf, (LPBYTE)szPassword, (DWORD)strlen(szPassword), pbSalt, (DWORD)cbSalt, STRONG_ITERATIONS, pbDerivedKey, 32))
	{
		if (bForDecrypt)
			_tprintf(_T("Error!\nAn unexpected error occured while creating the decryption key (Code 0x%.8X). Aborting...\n"), GetLastError());
		else
			_tprintf(_T("Error!\nAn unexpected error occured while creating the encryption key (Code 0x%.8X). Aborting...\n"), GetLastError());
		iStatus = -1;
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
				cbData = (DWORD)fread(pbData, 1, 16, fin);
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
								cbData = (DWORD)readLen;
								totalProcessed += (__int64)READ_BUFFER_SIZE;
								bFinal = (totalProcessed == inputLength) ? TRUE : FALSE;
								if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), bFinal))
								{
									if (cbData == fwrite(pbData, 1, cbData, fout))
									{
										ShowProgress(szOpDesc, inputLength, totalProcessed, bFinal);
									}
									else
									{
										_tprintf(_T("Not all decrypted bytes were written to disk. Aborting!\n"));
										iStatus = -2;
										break;
									}
								}
								else
								{
									iStatus = -3;
									_tprintf(_T("\nUnexpected error occured while decrypting data. Aborting!\n"));
									break;
								}
							}

							if ((iStatus == 0) && !bFinal)
							{
								if (ferror(fin))
								{
									_tprintf(_T("Unexpected error occured while reading data from input file. Aborting!\n"));
									iStatus = -1;
								}
								else
								{
									cbData = (DWORD)readLen;
									totalProcessed += (__int64)readLen;
									if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), TRUE))
									{
										if (cbData == fwrite(pbData, 1, cbData, fout))
										{
											ShowProgress(szOpDesc, inputLength, totalProcessed, TRUE);
										}
										else
										{
											_tprintf(_T("Not all decrypted bytes were written to disk. Aborting!\n"));
											iStatus = -2;
										}
									}
									else {
										_tprintf(_T("Unexpected error occured while decrypting. Aborting!\n"));
										iStatus = -3;
									}
								}
							}
						}
						else
						{
							_tprintf(_T("Password incorrect or the input file is not a valid encrypted file. Aborting!\n"));
							iStatus = -4;
						}
					}
					else
					{
						_tprintf(_T("Unexpected error occured while decrypting. Aborting\n"));
						iStatus = -3;
					}
				}
				else
				{
					_tprintf(_T("Unexpected error occured while reading data from input file. Aborting\n"));
					iStatus = -1;
				}
			}
			else
			{
				/* write the random salt */
				/* write the random IV */

				if ((cbSalt !=fwrite(pbSalt, 1, cbSalt, fout)) || (16 != fwrite(pbIV, 1, 16, fout))){
					_tprintf(_T("An unexpected error occured while writing data to the output file. Aborting!\n"));
					iStatus = -2;
					return iStatus;
				}

				/* protect encryption memory against swaping */
				VirtualLock(pbData, sizeof(pbData));

				memcpy(pbData, pbHeader, 16);
				cbData = 16;

				if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE))
				{
					fwrite(pbData, 1, cbData, fout);
					startClock = clock();
					while ((readLen = fread(pbData, 1, READ_BUFFER_SIZE, fin)) == READ_BUFFER_SIZE)
					{
						cbData = (DWORD)READ_BUFFER_SIZE;
						bStatus = AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE);
						if (bStatus)
						{
							totalProcessed += (__int64)READ_BUFFER_SIZE;
							if (cbData == fwrite(pbData, 1, cbData, fout))
							{
								ShowProgress(szOpDesc, inputLength, totalProcessed, FALSE);
							}
							else
							{
								_tprintf(_T("Not all encrypted bytes were written to disk. Aborting!\n"));
								iStatus = -2;
								break;
							}
						}
						else
						{
							_tprintf(_T("Unexpected error occured while encrypting. Aborting\n"));
							iStatus = -3;
							break;
						}
					}

					if (iStatus == 0)
					{
						if (ferror(fin))
						{
							_tprintf(_T("Unexpected error occured while reading data from input file. Aborting\n"));
							iStatus = -1;
						}
						else
						{
							cbData = (DWORD)readLen;
							if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), TRUE))
							{
								totalProcessed += (__int64)readLen;
								if (cbData == fwrite(pbData, 1, cbData, fout))
								{
									ShowProgress(szOpDesc, inputLength, totalProcessed, TRUE);
								}
								else
								{
									_tprintf(_T("Not all encrypted bytes were written to disk. Aborting!\n"));
									iStatus = -2;
								}
							}
							else {
								_tprintf(_T("Unexpected error occured while encrypting. Aborting\n"));
								iStatus = -3;
							}
						}
					}
				}
				else {
					_tprintf(_T("Unexpected error occured while encrypting. Aborting\n"));
					iStatus = -3;
				}
			}

			if (iStatus == 0)
			{
				_tprintf(_T("Flushing output file data to disk, please wait..."));
				_tprintf(_T("\rInput file %s successfully as \"%s\"\n"), bForDecrypt ? _T("decrypted") : _T("encrypted"), foutPath);
			}

		}
		else
		{
			_tprintf(_T("Error! Aborting!\n"));
			iStatus = -1;
		}
	}
	return iStatus;
}

int opEncDir(WIN32_FIND_DATA f, HANDLE h, const WCHAR finPath[], const WCHAR foutPath[], char szPassword[], PRF *pPrf, size_t cbSalt)
{
	FILE* fin=NULL;
	FILE* fout=NULL;
	wstring fileName, fileInPath, fileOutPath;
	__int64 inputLength;
	int iStatus = 0;

	do {
		fileName = wstring(f.cFileName);
		if ((fileName.compare(L".") == 0 && fileName.length() == 1) || (fileName.compare(L"..") == 0 && fileName.length() == 2)) {
			if (FindNextFile(h, &f) == 0) break;
			continue;
		}
		if ((f.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0) {

			fileOutPath = foutPath;
			fileOutPath += fileName;
			fileOutPath += L"\\";

			fileInPath = (wstring(finPath)).substr(0, ((wstring)finPath).length() - 1);
			fileInPath += fileName;
			fileInPath += L"\\*";

			if (!CreateDirectory(fileOutPath.c_str(), NULL) && ERROR_ALREADY_EXISTS != GetLastError()) {
				printf("Could not create/open the output folder %ws . (%d). Aborting...\n", fileOutPath.c_str(), GetLastError());
				iStatus = -1;
				return iStatus;
			}
			WIN32_FIND_DATA F;
			iStatus = opEncDir(F, FindFirstFile(fileInPath.c_str(), &F), fileInPath.c_str(), fileOutPath.c_str(), szPassword, pPrf, cbSalt);
		}
		else {

			fileInPath = (wstring(finPath)).substr(0, ((wstring)finPath).length() - 1);
			fileInPath += fileName;

			fileOutPath = foutPath;
			fileOutPath += fileName;
			fileOutPath += L".idx";

			fin = _tfopen(fileInPath.c_str(), _T("rb"));

			if (!fin)
			{
				_tprintf(_T("Failed to open the input file (%ws) for reading. Aborting...\n"), fileInPath.c_str());
				iStatus = -1;
				return iStatus;
			}

			if ((inputLength = _filelengthi64(_fileno(fin))) == 0)
			{
				_tprintf(_T("The input file %ws is empty. Aborting...\n"), fileInPath.c_str());
				iStatus = -1;
				return iStatus;
			}

			fout = _tfopen(fileOutPath.c_str(), _T("wb"));
			if (!fout)
			{
				_tprintf(_T("Failed to open the output file %ws for writing. Aborting...\n"), fileOutPath.c_str());
				iStatus = -1;
				return iStatus;
			}

			iStatus = opFile(fin, fout, fileOutPath.c_str(), szPassword, FALSE, pPrf, cbSalt);
		}

		if (iStatus != 0) {
			return iStatus;
		}

		if (fout) {
			fclose(fout);
			fout = NULL;
		}

		if (FindNextFile(h, &f) == 0) break;
	} while (1);
	
	return iStatus;
}

int opDecDir(WIN32_FIND_DATA f, HANDLE h, const WCHAR finPath[], const WCHAR foutPath[], char szPassword[], PRF *pPrf, size_t cbSalt)
{
	FILE* fin=NULL;
	FILE* fout=NULL;
	wstring fileName, fileInPath, fileOutPath;
	__int64 inputLength;
	int iStatus = 0;

	do {
		fileName = wstring(f.cFileName);
		if ((fileName.compare(L".") == 0 && fileName.length() == 1) || (fileName.compare(L"..") == 0 && fileName.length() == 2)) {
			if (FindNextFile(h, &f) == 0) break;
			continue;
		}
		if ((f.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0) {

			fileOutPath = foutPath;
			fileOutPath += fileName;
			fileOutPath += L"\\";

			fileInPath = (wstring(finPath)).substr(0, (wstring(finPath)).length() - 1);
			fileInPath += fileName;
			fileInPath += L"\\*";

			if (!CreateDirectory(fileOutPath.c_str(), NULL) && ERROR_ALREADY_EXISTS != GetLastError()) {
				printf("\nCould not create/open the output folder %ws . (%d). Aborting...\n", fileOutPath.c_str(), GetLastError());
				iStatus = -1;
				return iStatus;
			}
			WIN32_FIND_DATA F;
			iStatus = opDecDir(F, FindFirstFile(fileInPath.c_str(), &F), fileInPath.c_str(), fileOutPath.c_str(), szPassword, pPrf, cbSalt);
		}
		else {

			fileInPath = (wstring(finPath)).substr(0, (wstring(finPath)).length() - 1);
			fileInPath += fileName;

			fileOutPath = foutPath;

			fin = _tfopen(fileInPath.c_str(), _T("rb"));

			if (!fin)
			{
				_tprintf(_T("\nFailed to open the input file %ws for reading. Aborting...\n"), fileInPath.c_str());
				iStatus = -1;
				return iStatus;
			}

			if ((inputLength = _filelengthi64(_fileno(fin))) == 0)
			{
				_tprintf(_T("\nThe input file %ws is empty. Aborting...\n"), fileInPath.c_str());
				iStatus = -1;
				return iStatus;
			}

			if (fileName.substr(fileName.length() - 4, 4).compare(wstring(L".idx")) != 0)
			{
				_tprintf(_T("\nError : input file %ws is not a valid idx file. Aborting...\n"), fileInPath.c_str());
				iStatus = -1;
				return iStatus;
			}

			if ((inputLength < (__int64)(48 + cbSalt)) || (inputLength % 16))
			{
				_tprintf(_T("\nError : input file %ws is not a valid encrypted file. Aborting...\n"), fileInPath.c_str());
				iStatus = -1;
				return iStatus;
			}

			fileOutPath += fileName.substr(0, fileName.length() - 4);
			fout = _tfopen(fileOutPath.c_str(), _T("wb"));

			if (!fout)
			{
				_tprintf(_T("\nFailed to open the output file %ws for writing. Aborting...\n"), fileOutPath.c_str());
				iStatus = -1;
				return iStatus;
			}

			iStatus = opFile(fin, fout, fileOutPath.c_str(), szPassword, TRUE, pPrf, cbSalt);
		}

		if (iStatus != 0) {
			return iStatus; // To end all loops, not only the internal one (break)
		}

		if (fout) {
			fclose(fout);
			fout = NULL;
		}
		
		if (FindNextFile(h, &f) == 0) break;
	} while (1);
	return iStatus;
}

int opDir(WIN32_FIND_DATA f, HANDLE h, const WCHAR finPath[], const WCHAR foutPath[], char szPassword[], PRF *pPrf, size_t cbSalt, BOOL bForDecrypt)
{
	if (bForDecrypt) return(opDecDir(f, h, finPath, foutPath, szPassword, pPrf, cbSalt));
	else return(opEncDir(f, h, finPath, foutPath, szPassword, pPrf, cbSalt));
}

WCHAR* getAbsolutePath(WCHAR* relativePath)
{
	DWORD len = GetFullPathNameW(relativePath, 0, NULL, NULL);
	// len contains the size, in TCHARs, of the buffer that is required to hold the path and the terminating null character.
	WCHAR* dir = (WCHAR*)malloc(len*sizeof(WCHAR));

	DWORD temp = GetFullPathNameW(relativePath, len, dir, NULL);
	// temp contains, if succeeds, the size, in TCHARs, of the buffer that is required to hold the path without the terminating null character.

	// Since the path is relative, it is limited to MAX_PATH = 260 chars. No need to prepend "\\?\"

	if (temp == 0) {
		printf("An error occured while transforming the relative path to an absolute path! Aborting... (%d)\n", GetLastError());
		return NULL;
	}
	return dir;
}

int _tmain(int argc, TCHAR* argv[])
{  
	int iStatus = 0;
	
	FILE* fin = NULL;
	FILE* fout = NULL;
	int i, iLen;
	char szPassword[129]; // maximum 128 UTF8 bytes
	
	__int64 inputLength;
	
	BOOL bForDecrypt = FALSE;
	PRF* pPrf = &sha256Prf; // PBKDF2-SHA256 is used by default
	size_t cbSalt = 16; // 16 bytes salt for SHA-256 and 64-bytes otherwise

	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	BOOL isFile = TRUE;
	wstring fullInPath;
	wstring fullOutPath;
	WCHAR *inDir, *outDir;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	_tprintf(_T("\nidxcrypt - Simple yet Strong file encryptor. By IDRASSI Mounir (mounir@idrix.fr)\n\nCopyright 2017 IDRIX\n\n\n"));

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
					// missing hash algorithm               
					ShowUsage ();
					iStatus = -1;
					goto main_end;
            }

            if (_tcsicmp(argv[i+1], _T("sha256")) == 0) pPrf = &sha256Prf;
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
				// unexpected hash algorithm            
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
				// unexpected parameter
				ShowUsage ();
				iStatus = -1;
				goto main_end;
         }
      }
	}

	// Test whether argv[1] and argv[3] are relative to the current working directory or absolute 
	// Rule applied is detailed in https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx#fully_qualified_vs._relative_paths
	// Because we cannot use the "\\?\" prefix with a relative path, it is always limited to a total of MAX_PATH = 260 characters (cannot be extended)

	// To get the maximum length possible on Windows on runtime and remove the MAX_PATH limitation

	fullInPath = L"\\\\?\\";
	fullOutPath = L"\\\\?\\";

	if (PathIsRelativeW(argv[1])) {
		if ((inDir = getAbsolutePath(argv[1])) == NULL) {
			iStatus = -1;
			goto main_end;
		}
		fullInPath += inDir;
	}
	else fullInPath += argv[1];

	if (PathIsRelativeW(argv[3])) {
		if ((outDir = getAbsolutePath(argv[3])) == NULL) {
			iStatus = -1;
			goto main_end;
		}
		fullOutPath += outDir;
	}
	else fullOutPath += argv[3];

	// Stores information about the first file/folder which path corresponds to argv[1] in FindFileData
	hFind = FindFirstFileW(fullInPath.c_str(), &FindFileData);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		// We cannot know whether it is a file or a folder since it cannot even be found
		printf("File/folder %ws not found (%d). Aborting...\n", fullInPath.c_str(), GetLastError()); // 2 = ERROR_FILE_NOT_FOUND
		iStatus = -1; 
		goto main_end;
	}
	else {
		// Determine whether argv[1] is a file or a folder
		FindFileData.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY ? isFile = FALSE : isFile = TRUE;

		if (isFile) {
			fin = _tfopen(fullInPath.c_str(), _T("rb"));
			if (!fin)
			{
				_tprintf(_T("Failed to open the input file %ws for reading\n. Aborting..."), fullInPath.c_str());
				iStatus = -1;
				goto main_end;
			}

			if ((inputLength = _filelengthi64(_fileno(fin))) == 0)
			{
				_tprintf(_T("The input file %ws is empty. No action will be performed. Aborting...\n"), fullInPath.c_str());
				iStatus = -1;
				goto main_end;
			}

			if (bForDecrypt && ((fullInPath.substr(fullInPath.length() - 4, 4).compare(wstring(L".idx"))!=0) || (inputLength < (__int64)(48 + cbSalt)) || (inputLength % 16)))
			{
				_tprintf(_T("Error : input file %ws is not a valid encrypted file. Aborting...\n"), fullInPath.c_str());
				iStatus = -1;
				goto main_end;
			}

			// Check whether the user entered the output file with the correct extension ".idx"
			// Add it if it's not the case, before creating the file
			if (!bForDecrypt) {
				if (fullOutPath.substr(fullOutPath.length()-4, 4).compare(wstring(L".idx"))!=0) fullOutPath += wstring(L".idx");
			}

			fout = _tfopen(fullOutPath.c_str(), _T("wb"));
			if (!fout)
			{
				_tprintf(_T("Failed to open the output file %ws for writing. Aborting...\n"), fullOutPath.c_str());
				iStatus = -1;
				goto main_end;
			}

		}
		else {
			// If there is an error creating the output directory and this error is not ERROR_ALREADY_EXISTS
			if (CreateDirectory(fullOutPath.c_str(), NULL)==0 && ERROR_ALREADY_EXISTS != GetLastError()) {
				printf("Could not create/open the output folder %ws . (%d). Aborting...\n", fullOutPath.c_str(), GetLastError());
				iStatus = -1;
				goto main_end;
			}

			if (fullInPath.c_str()[fullInPath.length() - 1] != L'\\') fullInPath += L"\\";
			fullInPath += L"*";

			if (fullOutPath.c_str()[fullOutPath.length() - 1] != L'\\') fullOutPath += L"\\";

			hFind = FindFirstFile(fullInPath.c_str(), &FindFileData);
		}
	}

	// protect password memory against swaping //
	VirtualLock(szPassword, sizeof(szPassword));

	// convert the password to UTF8 //
	iLen = WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, NULL, 0, NULL, NULL);
	if (iLen > sizeof(szPassword))
	{
		DWORD dwErr = GetLastError();
		_tprintf(_T("Password is too long. Maximum allowed length is %d. Aborting...\n"), (sizeof(szPassword) - 1));
		iStatus = -1;
		goto main_end;
	}

	if (!WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, szPassword, sizeof(szPassword), NULL, NULL))
	{
		DWORD dwErr = GetLastError();
		_tprintf(_T("An unexpected error occured while converting the password (Code 0x%.8X). Aborting...\n"), dwErr);
		iStatus = -1;
		goto main_end;
	}

	// clear the password in the command line //
	SecureZeroMemory(argv[2], _tcslen(argv[2]) * sizeof(TCHAR));

	if (isFile) iStatus = opFile(fin, fout, fullOutPath.c_str(), szPassword, bForDecrypt, pPrf, cbSalt);
	else iStatus = opDir(FindFileData, hFind, fullInPath.c_str(), fullOutPath.c_str(), szPassword, pPrf, cbSalt, bForDecrypt);

	main_end : SecureZeroMemory(szPassword, sizeof(szPassword));
	if (fin) fclose(fin);
	if (fout)
	{
		fclose(fout);
		// delete the file in case of error //
		if (iStatus != 0) DeleteFile(fullOutPath.c_str());
	}

	return iStatus;
	
}
