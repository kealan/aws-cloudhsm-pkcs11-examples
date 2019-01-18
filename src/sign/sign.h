
#ifndef AWS_CLOUDHSM_PKCS11_SIGN_H
#define AWS_CLOUDHSM_PKCS11_SIGN_H

#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include "common.h"

CK_RV hsm_main(CK_SESSION_HANDLE session);
CK_RV generate_signature(CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE key,
                         CK_MECHANISM_TYPE mechanism,
                         CK_BYTE_PTR data,
                         CK_ULONG data_length,
                         CK_BYTE_PTR signature,
                         CK_ULONG_PTR signature_length);
CK_RV verify_signature(CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE key,
                       CK_MECHANISM_TYPE mechanism,
                       CK_BYTE_PTR data,
                       CK_ULONG data_length,
                       CK_BYTE_PTR signature,
                       CK_ULONG signature_length);


#endif
