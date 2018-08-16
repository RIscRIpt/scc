#pragma once

#include <scb/Bytes.h>

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

        RSA(unsigned bits, scb::Bytes const &publicExponent);
        RSA(scb::Bytes const &modulus, scb::Bytes const &exponent);
        ~RSA();

        RSA(RSA &&other) = default;
        RSA& operator=(RSA &&rhs) = default;

        RSA(RSA const &other) = delete;
        RSA& operator=(RSA const &rhs) = delete;

        scb::Bytes transorm(scb::Bytes const &bytes) const;

        scb::Bytes get_modulus() const;
        scb::Bytes get_public_exponent() const;
        scb::Bytes get_private_exponent() const;

    private:
        void free();

        void *rsa_;
    };

}
