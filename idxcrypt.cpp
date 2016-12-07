/*
 * A small utility to encrypt/decrypt files using AES256 and strong password key derivation.
 *
 * The AES256 key is derived from password using PBKDF2-SHA256 with 500000 iterations.
 * 
 * All cryptographic operations are done using Windows Crypto API.
 *
 * Copyright (c) 2014 Mounir IDRASSI <mounir.idrassi@idrix.fr>. All rights reserved.
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
typedef struct
{
   DWORD	magic;			/* used to help check that we are using the correct context */
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
   DWORD             cbHmacLength;
} PRF;


/* Implementation of HMAC-SHA256 using CAPI */

#define HMAC_SHA256_MAGIC 0x53484132

typedef struct
{
   HCRYPTPROV hProv;
   HCRYPTKEY hKey;
} CAPI_CTX_PARAM;

// Structure used by CAPI for HMAC computation
typedef struct {
   BLOBHEADER hdr;
   DWORD cbKeySize;
} HMAC_KEY_BLOB;

BOOL WINAPI hmacInit_sha256(
   PRF_CTX*       pContext,   /* PRF context used in HMAC computation */
   unsigned char* pbKey,      /* pointer to authentication key */
   DWORD          cbKey       /* length of authentication key */                        
)
{
   HCRYPTPROV hProv = NULL;
   HCRYPTKEY hKey = NULL;
   HMAC_KEY_BLOB *pKeyBlob = (HMAC_KEY_BLOB *) LocalAlloc(0, sizeof(HMAC_KEY_BLOB) + cbKey + 32); // we put enough room for 0's padding
   BOOL bStatus = FALSE;
   DWORD dwError = 0, dwLen;

   pKeyBlob->hdr.bType = PLAINTEXTKEYBLOB;
   pKeyBlob->hdr.bVersion = CUR_BLOB_VERSION;
   pKeyBlob->hdr.reserved = 0;
   pKeyBlob->hdr.aiKeyAlg = CALG_RC2;
   pKeyBlob->cbKeySize = cbKey;
   memcpy(((LPBYTE) pKeyBlob) + sizeof(HMAC_KEY_BLOB), pbKey, cbKey);

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

   dwLen = sizeof(HMAC_KEY_BLOB) + cbKey;
   if (dwLen < 32)
   {
      // we pad with zeros till the size of SHA512 digest.
      // this is to avoid erros under Windows 8.1 wich doesn't accept 1-byte RC2 keys
	  // the result will be the same since the HMAC-SHA512 will perform the same padding
	  DWORD dwPad = 32 - dwLen;
	  memset(((LPBYTE) pKeyBlob) + dwLen, 0, dwPad);
	  dwLen += dwPad;
	  pKeyBlob->cbKeySize += dwPad;
   }

   if (!CryptImportKey(hProv, (LPBYTE) pKeyBlob, dwLen, NULL, CRYPT_IPSEC_HMAC_KEY, &hKey))
   {
      dwError = GetLastError();
      goto hmacInit_end;
   }

   CAPI_CTX_PARAM* pParam = (CAPI_CTX_PARAM*) LocalAlloc(0, sizeof(CAPI_CTX_PARAM));
   pParam->hProv = hProv;
   pParam->hKey = hKey;

   pContext->magic = HMAC_SHA256_MAGIC;
   pContext->pParam = (void*) pParam;

   hProv = NULL;
   hKey = NULL;

   bStatus = TRUE;

hmacInit_end:

   if (hKey) CryptDestroyKey(hKey);
   if (hProv) CryptReleaseContext(hProv, 0);

   if (pKeyBlob) LocalFree(pKeyBlob);

   SetLastError(dwError);
   return bStatus;
}

BOOL WINAPI hmac_sha256(
   PRF_CTX*       pContext,               /* PRF context used in HMAC computation */  
   unsigned char*  pbData,                /* pointer to data stream */
   DWORD           cbData,                /* length of data stream */
   unsigned char   pbDigest[32]           /* caller digest to be filled in */
)
{
   HCRYPTPROV hProv = NULL;
   HCRYPTHASH hHash = NULL;
   HCRYPTKEY hKey = NULL;
   DWORD cbDigest = 32;
   HMAC_INFO   HmacInfo;
   BOOL bStatus = FALSE;
   DWORD dwError = 0;

   ZeroMemory(&HmacInfo, sizeof(HmacInfo));
	HmacInfo.HashAlgid = CALG_SHA_256;

   if (!pContext || (pContext->magic != HMAC_SHA256_MAGIC) || (!pContext->pParam))
   {
      dwError = ERROR_BAD_ARGUMENTS;
      goto hmac_end;
   }

   hProv = ((CAPI_CTX_PARAM*) pContext->pParam)->hProv;
   hKey = ((CAPI_CTX_PARAM*) pContext->pParam)->hKey;

   if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash))
   {
      dwError = GetLastError();
      goto hmac_end;
   }

   if (!CryptSetHashParam( hHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0))
   {
      dwError = GetLastError();
      goto hmac_end;
   }

   if (!CryptHashData(hHash, pbData, cbData, 0))
   {
      dwError = GetLastError();
      goto hmac_end;
   }

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


BOOL WINAPI hmacFree_sha256(
   PRF_CTX*       pContext          /* PRF context used in HMAC computation */  
)
{
   HCRYPTPROV hProv = NULL;
   HCRYPTKEY hKey = NULL;

   if (!pContext || (pContext->magic != HMAC_SHA256_MAGIC) || (!pContext->pParam))
   {
      SetLastError(ERROR_BAD_ARGUMENTS);
      return FALSE;
   }

   hProv = ((CAPI_CTX_PARAM*) pContext->pParam)->hProv;
   hKey = ((CAPI_CTX_PARAM*) pContext->pParam)->hKey;

   CryptDestroyKey(hKey);
   CryptReleaseContext(hProv, 0);

   LocalFree(pContext->pParam);
   SecureZeroMemory(pContext, sizeof(PRF_CTX));

   return TRUE;
}

/*
 * Definition of the HMAC-SHA256 PRF
 */
PRF sha256Prf = {hmacInit_sha256, hmac_sha256, hmacFree_sha256, 32};


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
   DWORD hlen = pPrf.cbHmacLength;
   LPBYTE Ti = (LPBYTE) LocalAlloc(0, hlen);
   LPBYTE V = (LPBYTE) LocalAlloc(0, hlen);
   LPBYTE U = (LPBYTE) LocalAlloc(0, max((cbSalt + 4), hlen));
   DWORD dwULen;
   PRF_CTX prfCtx = {0};

   if (!pbDerivedKey || !cbDerivedKey || (!pbPassword && cbPassword) )
   {
      dwError = ERROR_BAD_ARGUMENTS;
      goto PBKDF2_end;
   }

   if (!Ti || !U || !V)
   {
      dwError = ERROR_NOT_ENOUGH_MEMORY;
      goto PBKDF2_end;
   }

   l = (DWORD) ceil((double) cbDerivedKey / (double) hlen);
   r = cbDerivedKey - (l - 1) * hlen;

   if (!pPrf.hmacInit(&prfCtx, pbPassword, cbPassword))
   {
      dwError = GetLastError();
      goto PBKDF2_end;
   }

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

int _tmain(int argc, TCHAR* argv[])
{  
	int iStatus = 0;
	BYTE pbDerivedKey[256];
	BYTE pbSalt[16], pbIV[16];
	FILE* fin = NULL;
	FILE* fout = NULL;
	int iLen;
	char szPassword[129]; // maximum 128 UTF8 bytes
	BYTE pbData[READ_BUFFER_SIZE + 32];
	DWORD cbData;
	__int64 inputLength;
	size_t readLen;
	BOOL bForDecrypt;
	
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	_tprintf(_T("\nidxcrypt - Simple file encryptor. By IDRASSI Mounir (mounir@idrix.fr)\n\nCopyright 2014 IDRIX\n\n\n"));

	if ((argc != 4 && argc != 5) || (argc == 5 && _tcsicmp(argv[4], _T("/d"))))
	{
		_tprintf(_T("Wrong parameters list.\nUsage : idxcrypt InputFile Password OutputFile [/d]\n"));
		iStatus = -1;
		goto main_end;
	}

	bForDecrypt = (argc == 5)? TRUE : FALSE;

	fin = _tfopen(argv[1], _T("rb"));
	if (!fin)
	{
		_tprintf(_T("Failed to open the input file for reading\n"));
		iStatus = -1;
		goto main_end;
	}


	if ((inputLength = _filelengthi64(_fileno(fin))) == 0)
	{
		_tprintf(_T("The input file is empty. No encryption will be performed.\n"));
		iStatus = -1;
		goto main_end;
	}

	if (bForDecrypt && (inputLength < 64 || (inputLength % 16)))
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
		if ((16 != fread(pbSalt, 1, 16, fin)) || (16 != fread(pbIV, 1, 16, fin)))
		{
			_tprintf(_T("An unexpected error occured while reading the input file\n"));
			iStatus = -1;
			goto main_end;
		}
	}
	else
	{
		/* generate random salt */
		if (!GenerateRandom(pbSalt, 16) || !GenerateRandom(pbIV, 16))
		{
			DWORD dwErr = GetLastError();
			_tprintf(_T("An unexpected error occured while preparing for the encryption (Code 0x%.8X)\n"), dwErr);
			iStatus = -1;
			goto main_end;
		}
	}

	if (bForDecrypt)
		printf("Generating the decryption key...");
	else
		printf("Generating the encryption key...");

   if (!PBKDF2(sha256Prf, (LPBYTE) szPassword, (DWORD) strlen(szPassword), pbSalt, 16, STRONG_ITERATIONS, pbDerivedKey, 32))
   {
		if (bForDecrypt)
			printf("Error!\nAn unexpected error occured while creating the decryption key (Code 0x%.8X)\n", GetLastError());
		else
			printf("Error!\nAn unexpected error occured while creating the encryption key (Code 0x%.8X)\n", GetLastError());
		iStatus = -1;
      goto main_end;
   }
	else
	{
		if (bForDecrypt)
			printf("Done!\nInitializing decryption...");
		else
			printf("Done!\nInitializing encryption...");
		AES_CTX ctx;
		if (AesInit(pbDerivedKey, pbIV, bForDecrypt, &ctx))
		{
			BYTE pbHeader[16];
			memcpy(pbHeader, "IDXCRYPTTPYRCXDI", 16);

			if (bForDecrypt)
				printf("Done!\nDecrypting the input file...");
			else
				printf("Done!\nEncrypting the input file...");

			if (bForDecrypt)
			{
				cbData = (DWORD) fread(pbData, 1, 16, fin);
				if ((cbData == 16) && AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE))
				{
					if ((cbData == 16) && (0 == memcmp(pbData, pbHeader, 16)))
					{
						while ((readLen = fread(pbData, 1, READ_BUFFER_SIZE, fin)) == READ_BUFFER_SIZE)
						{
							cbData = (DWORD) readLen;
							if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE))
							{
								fwrite(pbData,1,cbData,fout);
							}
							else
							{
								iStatus = -1;
								break;
							}
						}

						if (iStatus == 0)
						{
							cbData = (DWORD) readLen;
							if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), TRUE))
							{
								fwrite(pbData,1,cbData,fout);
							}
							else
								iStatus = -1;
						}

						if (iStatus != 0)
						{
							printf("Failed!\nUnexpected error occured while decrypting the input file\n");
						}
					}
					else
					{
						_tprintf(_T("Error : Password incorrect or the input file is not a valid encrypted file.\n"));
						iStatus = -1;
					}
				}
				else
				{
					printf("Failed!\nUnexpected error occured while decrypting the input file\n");
					iStatus = -1;
				}
			}
			else
			{
				/* write the random salt */
				fwrite(pbSalt,1,16,fout);

				/* write the random IV */
				fwrite(pbIV,1,16,fout);

				/* protect encryption memory against swaping */
				VirtualLock(pbData, sizeof(pbData));

				memcpy(pbData, pbHeader, 16);
				cbData = 16;

				if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE))
				{
					fwrite(pbData,1,cbData,fout);
					while ((readLen = fread(pbData, 1, READ_BUFFER_SIZE, fin)) == READ_BUFFER_SIZE)
					{
						cbData = (DWORD) readLen;
						if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), FALSE))
						{
							fwrite(pbData,1,cbData,fout);
						}
						else
						{
							iStatus = -1;
							break;
						}
					}

					if (iStatus == 0)
					{
						cbData = (DWORD) readLen;
						if (AesProcess(&ctx, pbData, &cbData, sizeof(pbData), TRUE))
						{
							fwrite(pbData,1,cbData,fout);
						}
						else
							iStatus = -1;
					}
				}
				else
					iStatus = -1;
			}

			if (iStatus == 0)
			{
				_tprintf(_T("Done!\nInput file %s successfully as \"%s\"\n"), bForDecrypt? _T("decrypted") : _T("encrypted"), argv[3]);
			}
			else if (!bForDecrypt)
			{
				_tprintf(_T("Failed!\nUnexpected error occured while %s the input file\n"), bForDecrypt? _T("decrypting") : _T("encrypting"), argv[3]);
			}

		}
		else
		{
			printf("Error!\n");
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
