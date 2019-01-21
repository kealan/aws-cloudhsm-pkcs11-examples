#include "sign.h"

/**
 * Generate an AES key.
 * @param session  Valid PKCS#11 Session.
 * @param key_length_bytes Byte size of key. Supported sizes are here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param key pointer to hold the resulting key handle.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_aes_key(CK_SESSION_HANDLE session,
                       CK_ULONG key_length_bytes,
                       CK_OBJECT_HANDLE_PTR key) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_GENERIC_SECRET_KEY_GEN, NULL, 0};
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;

    CK_ATTRIBUTE template[] = {
          {CKA_CLASS, &key_class, sizeof(key_class)},
          {CKA_SIGN, &true, sizeof(CK_BBOOL)},	  
          {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
          {CKA_VALUE_LEN, &key_length_bytes, sizeof(CK_ULONG)}
    };

    rv = funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
    return rv;
}


CK_RV hsm_main(CK_SESSION_HANDLE session) {
  
    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;
    CK_RV rv = generate_aes_key(session, 16, &aes_key);
    if (rv == CKR_OK) {
        printf("AES key generated. Key handle: %lu\n", aes_key);
    } else {
        printf("AES key generation failed: %lu\n", rv);
    }    

    CK_BYTE_PTR data = "TRS hash";
    CK_ULONG data_length = strlen(data);

    CK_BYTE signature[MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MAX_SIGNATURE_LENGTH;

    // Set the PKCS11 signature mechanism type.
    CK_MECHANISM_TYPE mechanism = CKM_SHA512_HMAC;

    rv = generate_signature(session, aes_key, mechanism,
                            data, data_length, signature, &signature_length);
    if (rv == CKR_OK) {
        unsigned char *hex_signature = NULL;
        bytes_to_new_hexstring(signature, signature_length, &hex_signature);
        if (!hex_signature) {
            printf("Could not allocate hex array\n");
            return 1;
        }

        printf("Data: %s\n", data);
        printf("Signature: %s\n", hex_signature);
    } else {
        printf("Signature generation failed: %lu\n", rv);
        return rv;
    }

    rv = verify_signature(session, aes_key, mechanism,
                          data, data_length, signature, signature_length);
    if (rv == CKR_OK) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return rv;
    }

    return CKR_OK;
}
