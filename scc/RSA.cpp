#include "RSA.h"
#include "Exception.h"

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

scc::RSA::RSA(scb::Bytes const &modulus, scb::Bytes const &exponent) {
    rsa_ = RSA_new();
    modulus_ = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), NULL);
    exponent_ = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), NULL);

    int result = RSA_set0_key(
        static_cast<::RSA*>(rsa_),
        static_cast<BIGNUM*>(modulus_),
        static_cast<BIGNUM*>(exponent_),
        NULL
    );

    if (!result) {
        free();
        throw Exception(result);
    }
}

scc::RSA::~RSA() {
    free();
}

scb::Bytes scc::RSA::transorm(scb::Bytes const &bytes) const {
    scb::Bytes result(BN_num_bits(static_cast<BIGNUM*>(modulus_)) / 8);
    if (
        RSA_public_decrypt(
            static_cast<int>(bytes.size()),
            bytes.data(),
            result.data(),
            static_cast<::RSA*>(rsa_),
            RSA_NO_PADDING
        ) == -1
    ) {
        throw Exception(ERR_get_error());
    }
    return result;
}

void scc::RSA::free() {
    if (rsa_) {
        RSA_free(static_cast<::RSA*>(rsa_));
        rsa_ = nullptr;
    }
    // RSA_free also frees modulus and exponent
}
