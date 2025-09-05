#include <stddef.h>

#ifdef CONFIG_ARCH_POSIX
#include <posix_board_if.h>
#endif

#include <zephyr/logging/log.h>

#include <external/pkcs11/pkcs11.h>

const int APP_SUCCESS = 0;
const int APP_ERROR = -1;

LOG_MODULE_REGISTER(persistent_key_usage, LOG_LEVEL_INF);

int main(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, NULL, 0};
    CK_OBJECT_HANDLE key_handle = 0;

    // Init
    rv = C_Initialize(NULL);
    if (rv != CKR_OK)
    {
        LOG_ERR("C_Initialize failed: 0x%lX", rv);
        return APP_ERROR;
    }
    LOG_INF("C_Initialize succeeded");

    // Generate/reuse key
    rv = C_GenerateKey(session, &mechanism, NULL, 0, &key_handle);
    if (rv != CKR_OK)
    {
        LOG_ERR("C_GenerateKey failed: 0x%lX", rv);
        return APP_ERROR;
    }
    LOG_INF("C_GenerateKey succeeded");

    // Encryption test
    CK_BYTE plaintext[] = "Sample text to be encrypted!";
    LOG_INF("Plaintext: %s", plaintext);
    CK_BYTE ciphertext[64];
    CK_ULONG ciphertext_len = sizeof(ciphertext);

    rv = C_Encrypt(session, plaintext, sizeof(plaintext), ciphertext, &ciphertext_len);
    if (rv != CKR_OK)
    {
        LOG_ERR("C_Encrypt failed: 0x%lX", rv);
        return APP_ERROR;
    }
    LOG_INF("Ciphertext length: %lu", ciphertext_len);

    // Decryption test
    CK_BYTE decrypted[64];
    CK_ULONG decrypted_len = sizeof(decrypted);

    rv = C_Decrypt(session, ciphertext, ciphertext_len, decrypted, &decrypted_len);
    if (rv != CKR_OK)
    {
        LOG_ERR("C_Dencrypt failed: 0x%lX", rv);
        return APP_ERROR;
    }


    LOG_INF("Decrypted: %s", decrypted);

    // Finalize
    rv = C_Finalize(NULL);
    if (rv != CKR_OK)
    {
        LOG_ERR("C_Finalize failed: 0x%lX", rv);
        return APP_ERROR;
    }

#ifdef CONFIG_ARCH_POSIX
    posix_exit(APP_SUCCESS);
#endif

    return APP_SUCCESS;
}
