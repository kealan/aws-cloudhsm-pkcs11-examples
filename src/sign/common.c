#include "sign.h"

CK_RV generate_signature(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE key,
                                CK_MECHANISM_TYPE mechanism,
                                CK_BYTE_PTR data,
                                CK_ULONG data_length,
                                CK_BYTE_PTR signature,
                                CK_ULONG_PTR signature_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_SignInit(session, &mech, key);
    if (rv != CKR_OK) {
        return !CKR_OK;
    }

    rv = funcs->C_Sign(session, data, data_length, signature, signature_length);
    return rv;
}

CK_RV verify_signature(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE key,
                              CK_MECHANISM_TYPE mechanism,
                              CK_BYTE_PTR data,
                              CK_ULONG data_length,
                              CK_BYTE_PTR signature,
                              CK_ULONG signature_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_VerifyInit(session, &mech, key);
    if (rv != CKR_OK) {
        return !CKR_OK;
    }

    rv = funcs->C_Verify(session, data, data_length, signature, signature_length);
    return rv;
}
