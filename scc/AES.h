#pragma once

#include "mode.h"
#include "operation.h"

#include <scb/Bytes.h>

namespace scc {

    class AES {
    public:
        AES(scb::Bytes const &key);

        scb::Bytes decrypt_ecb(scb::Bytes const &buffer) const;
        scb::Bytes encrypt_ecb(scb::Bytes const &buffer) const;
        scb::Bytes decrypt_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const;
        scb::Bytes encrypt_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const;
        scb::Bytes crypt(scb::Bytes const &buffer, operation::Operation operation, scb::Bytes const &iv) const;

        scb::Bytes const key;

    private:
        void const *get_cipher(mode::Mode mode) const;
        void validate_alignment(scb::Bytes const &buffer) const;
    };

}
