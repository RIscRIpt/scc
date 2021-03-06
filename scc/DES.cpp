#include "DES.h"

#include <openssl/des.h>

using namespace scc;

DES::DES(scb::Bytes const &key)
    : key(key)
{
    switch (key.size()) {
        case 8: break; // DES
        case 16: break; // DES3
        case 24: break; // DES3
        default:
            throw std::runtime_error("Unsupported DES key size");
    }
}

scb::Bytes DES::decrypt1_ecb(scb::Bytes const &buffer) const {
    return crypt1(buffer, operation::Decrypt, {});
}

scb::Bytes DES::encrypt1_ecb(scb::Bytes const &buffer) const {
    return crypt1(buffer, operation::Encrypt, {});
}

scb::Bytes DES::decrypt1_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const{
    if (!iv.empty())
        return crypt1(buffer, operation::Decrypt, iv);
    else
        return crypt1(buffer, operation::Decrypt, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, });
}

scb::Bytes DES::encrypt1_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const {
    if (!iv.empty())
        return crypt1(buffer, operation::Encrypt, iv);
    else
        return crypt1(buffer, operation::Encrypt, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, });
}

scb::Bytes DES::crypt1(scb::Bytes const &buffer, operation::Operation operation, scb::Bytes const &iv) const {
    validate_alignment(buffer);
    operation::validate(operation);
    validate_alignment(iv);

    scb::Bytes result(buffer.size());

    DES_key_schedule ks;
    DES_set_key_unchecked((const_DES_cblock*)key.data(), &ks);

    if (iv.empty()) {
        DES_ecb_encrypt((const_DES_cblock*)buffer.data(), (DES_cblock*)result.data(), &ks, operation);
    } else {
        DES_cbc_encrypt(buffer.data(), result.data(), static_cast<long>(buffer.size()), &ks, (DES_cblock*)iv.data(), operation);
    }

    return result;
}

scb::Bytes DES::decrypt3_ecb(scb::Bytes const &buffer) const {
    return crypt3(buffer, operation::Decrypt, {});
}

scb::Bytes DES::encrypt3_ecb(scb::Bytes const &buffer) const {
    return crypt3(buffer, operation::Encrypt, {});
}

scb::Bytes DES::decrypt3_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const{
    if (!iv.empty())
        return crypt3(buffer, operation::Decrypt, iv);
    else
        return crypt3(buffer, operation::Decrypt, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, });
}

scb::Bytes DES::encrypt3_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const {
    if (!iv.empty())
        return crypt3(buffer, operation::Encrypt, iv);
    else
        return crypt3(buffer, operation::Encrypt, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, });
}

scb::Bytes DES::crypt3(scb::Bytes const &buffer, operation::Operation operation, scb::Bytes const &iv) const {
    validate_alignment(buffer);
    operation::validate(operation);
    validate_alignment(iv);

    scb::Bytes result(buffer.size());

    DES_key_schedule ks1, ks2, ks3;
    DES_set_key_unchecked((const_DES_cblock*)(key.data() + 0), &ks1);
    DES_set_key_unchecked((const_DES_cblock*)(key.data() + 8), &ks2);
    if (key.size() == 16)
        DES_set_key_unchecked((const_DES_cblock*)(key.data() + 0), &ks3);
    else if (key.size() == 24)
        DES_set_key_unchecked((const_DES_cblock*)(key.data() + 16), &ks3);
    else
        throw std::runtime_error("invalid key size");

    if (iv.empty()) {
        result = buffer;
        if (operation == operation::Encrypt) {
            for (size_t i = 0; i < result.size(); i += 8)
                DES_encrypt3((DES_LONG*)(result.data() + i), &ks1, &ks2, &ks3);
        } else if (operation == operation::Decrypt) {
            for (size_t i = 0; i < result.size(); i += 8)
                DES_decrypt3((DES_LONG*)(result.data() + i), &ks1, &ks2, &ks3);
        } else {
            throw std::invalid_argument("invalid operation");
        }
    } else {
        DES_ede3_cbc_encrypt(buffer.data(), result.data(), static_cast<long>(buffer.size()), &ks1, &ks2, &ks3, (DES_cblock*)iv.data(), operation);
    }

    return result;
}

void DES::validate_alignment(scb::Bytes const & buffer) {
    if (buffer.size() & 0b111)
        throw std::invalid_argument("Buffer must be 8 byte aligned");
}
