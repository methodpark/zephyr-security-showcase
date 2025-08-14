#include <zephyr/logging/log.h>

#include <external/pkcs11/pkcs11.h>

LOG_MODULE_REGISTER(ul_pkcs11, LOG_LEVEL_INF);

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pInitArgs)
{
    return CKR_OK;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR pObjHdl)
{
    return CKR_OK;
}

// ---------- Encrypt ----------
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    return CKR_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData,
                CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen)
{
    return CKR_OK;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen,
                      CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen)
{
    return CKR_OK;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen)
{
    return CKR_OK;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen)
{
    return CKR_OK;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart,
                      CK_ULONG_PTR pulPartLen)
{
    return CKR_OK;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pLastPart,
                     CK_ULONG_PTR pulLastPartLen)
{
    return CKR_OK;
}
