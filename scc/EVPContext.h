#pragma once

#include <openssl/evp.h>

namespace scc {

    class EVPContext {
    public:
        EVPContext();
        ~EVPContext();

        EVPContext(EVPContext const &other) = delete;
        EVPContext& operator=(EVPContext const &rhs) = delete;

        EVPContext(EVPContext &&other) = default;
        EVPContext& operator=(EVPContext &&rhs) = default;

        inline operator EVP_CIPHER_CTX*() { return context; }

    private:
        EVP_CIPHER_CTX *context;
    };

}
