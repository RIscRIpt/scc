#pragma once

#include <scb/Bytes.h>

#include <openssl/rsa.h>

namespace scc {

    class RSA final {
    public:
        /*
        enum class Padding {
            PKCS1 = RSA_PKCS1_PADDING,
            SSLV23 = RSA_SSLV23_PADDING,
            No = RSA_NO_PADDING,
            PKCS1_OAEP = RSA_PKCS1_OAEP_PADDING,
            X931 = RSA_X931_PADDING,
        };
        */

        RSA(scb::Bytes const &modulus, scb::Bytes const &exponent);
        ~RSA();

        scb::Bytes transorm(scb::Bytes const &bytes) const;

    private:
        void free();

        ::RSA *rsa_;
        BIGNUM *modulus_;
        BIGNUM *exponent_;
    };

}
