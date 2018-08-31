#include "AES.h"
#include "EVPContext.h"
#include "Exception.h"

#include <openssl/err.h>
#include <openssl/evp.h>

using namespace scc;

AES::AES(scb::Bytes const &key)
    : key(key)
{
    switch (key.size()) {
        case 16: break; // AES128
        case 24: break; // AES192
        case 32: break; // AES256
        default:
            throw std::runtime_error("Unsupported AES key size");
    }
}

scb::Bytes AES::decrypt_ecb(scb::Bytes const &buffer) const {
    return crypt(buffer, operation::Decrypt, {});
}

scb::Bytes AES::encrypt_ecb(scb::Bytes const &buffer) const {
    return crypt(buffer, operation::Encrypt, {});
}

scb::Bytes AES::decrypt_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const {
    if (!iv.empty())
        return crypt(buffer, operation::Decrypt, iv);
    else
        return crypt(buffer, operation::Decrypt, scb::Bytes(key.size()));
}

scb::Bytes AES::encrypt_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const {
    if (!iv.empty())
        return crypt(buffer, operation::Encrypt, iv);
    else
        return crypt(buffer, operation::Encrypt, scb::Bytes(key.size()));
}

scb::Bytes AES::crypt(scb::Bytes const &buffer, operation::Operation operation, scb::Bytes const &iv) const {
    validate_alignment(buffer);

    scb::Bytes cipher(buffer.size() + 32 /* maximum block size */);
    int result_size = static_cast<int>(cipher.size());

    int result;
    EVPContext context;

    result = EVP_CipherInit_ex(
        context,
        static_cast<EVP_CIPHER const*>(get_cipher(iv.empty() ? mode::ECB : mode::CBC)),
        NULL,
        key.data(),
        iv.empty() ? NULL : iv.data(),
        operation
    );
    if (!result)
        throw Exception(ERR_get_error());

    result = EVP_CipherUpdate(context, cipher.data(), &result_size, buffer.data(), static_cast<int>(buffer.size()));
    if (!result)
        throw Exception(ERR_get_error());

    result = EVP_CipherFinal_ex(context, cipher.data() + result_size, &result_size);
    if (!result)
        throw Exception(ERR_get_error());

    cipher.resize(result_size);

    return cipher;
}

void const* AES::get_cipher(mode::Mode mode) const {
    switch (key.size()) {
        case 16:
            return mode == mode::ECB ? EVP_aes_128_ecb() : EVP_aes_128_cbc();
        case 24:
            return mode == mode::ECB ? EVP_aes_192_ecb() : EVP_aes_192_cbc();
        case 32:
            return mode == mode::ECB ? EVP_aes_256_ecb() : EVP_aes_256_cbc();
        default:
            throw std::runtime_error("Unsupported AES key size");
    }
}

void AES::validate_alignment(scb::Bytes const &buffer) const {
    if (buffer.size() % key.size() != 0)
        throw std::invalid_argument("Buffer must be 8 byte aligned");
}
