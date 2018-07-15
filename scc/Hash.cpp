#include "Hash.h"

#include <openssl/sha.h>

scb::Bytes scc::SHA1(scb::Bytes const &buffer) {
    scb::Bytes result(SHA_DIGEST_LENGTH);
    ::SHA1(buffer.data(), buffer.size(), result.data());
    return result;
}

scb::Bytes scc::SHA224(scb::Bytes const &buffer) {
    scb::Bytes result(SHA224_DIGEST_LENGTH);
    ::SHA224(buffer.data(), buffer.size(), result.data());
    return result;
}

scb::Bytes scc::SHA256(scb::Bytes const &buffer) {
    scb::Bytes result(SHA256_DIGEST_LENGTH);
    ::SHA256(buffer.data(), buffer.size(), result.data());
    return result;
}

scb::Bytes scc::SHA384(scb::Bytes const &buffer) {
    scb::Bytes result(SHA384_DIGEST_LENGTH);
    ::SHA384(buffer.data(), buffer.size(), result.data());
    return result;
}

scb::Bytes scc::SHA512(scb::Bytes const &buffer) {
    scb::Bytes result(SHA512_DIGEST_LENGTH);
    ::SHA512(buffer.data(), buffer.size(), result.data());
    return result;
}
