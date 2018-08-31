#include "EVPContext.h"

#include <openssl/evp.h>

using namespace scc;

EVPContext::EVPContext()
    : context(EVP_CIPHER_CTX_new())
{}

EVPContext::~EVPContext() {
    if (context != nullptr) {
        EVP_CIPHER_CTX_free(context);
        context = nullptr;
    }
}
