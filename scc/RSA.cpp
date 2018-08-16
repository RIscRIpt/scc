#include "RSA.h"
#include "Exception.h"

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

scc::RSA::RSA(unsigned bits, scb::Bytes const &publicExponent) {
    rsa_ = RSA_new();
    auto BNpublicExponent = BN_bin2bn(publicExponent.data(), static_cast<int>(publicExponent.size()), NULL);

    int result = RSA_generate_key_ex(
        static_cast<::RSA*>(rsa_),
        bits,
        BNpublicExponent,
        NULL
    );

    if (!result) {
        free();
        throw Exception(result);
    }
}

scc::RSA::RSA(scb::Bytes const &modulus, scb::Bytes const &exponent) {
    rsa_ = RSA_new();
    auto BNmodulus = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), NULL);
    auto BNexponent = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), NULL);

    int result = RSA_set0_key(
        static_cast<::RSA*>(rsa_),
        static_cast<BIGNUM*>(BNmodulus),
        static_cast<BIGNUM*>(BNexponent),
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
    BIGNUM const *modulus = NULL;
    RSA_get0_key(static_cast<::RSA*>(rsa_), &modulus, NULL, NULL);
    if (!modulus)
        throw std::runtime_error("failed to get modulus");
    scb::Bytes result(BN_num_bytes(modulus));
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

scb::Bytes scc::RSA::get_modulus() const {
    BIGNUM const *modulus = NULL;
    RSA_get0_key(static_cast<::RSA*>(rsa_), &modulus, NULL, NULL);
    if (!modulus)
        return {};
    scb::Bytes result(BN_num_bytes(modulus));
    BN_bn2bin(modulus, result.data());
    return result;
}

scb::Bytes scc::RSA::get_public_exponent() const {
    BIGNUM const *exponent = NULL;
    RSA_get0_key(static_cast<::RSA*>(rsa_), NULL, &exponent, NULL);
    if (!exponent)
        return {};
    scb::Bytes result(BN_num_bytes(exponent));
    BN_bn2bin(exponent, result.data());
    return result;
}

scb::Bytes scc::RSA::get_private_exponent() const {
    BIGNUM const *exponent = NULL;
    RSA_get0_key(static_cast<::RSA*>(rsa_), NULL, NULL, &exponent);
    if (!exponent)
        return {};
    scb::Bytes result(BN_num_bytes(exponent));
    BN_bn2bin(exponent, result.data());
    return result;
}

void scc::RSA::free() {
    if (rsa_) {
        RSA_free(static_cast<::RSA*>(rsa_));
        rsa_ = nullptr;
    }
    // RSA_free also frees modulus and exponent
}
