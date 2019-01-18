#include "sign.h"

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return 1;
    }

    rv = pkcs11_initialize(args.library);
    rv = pkcs11_open_session(args.pin, &session);
    if (rv != CKR_OK)
        return 0;

    printf("Sign/verify with hmac\n");
    hsm_main(session);
}
