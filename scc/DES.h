#pragma once

#include <scb/Bytes.h>

namespace scc {

    class DES {
    public:
        enum Mode {
            ECB,
            CBC,
        };

        enum Operation {
            Decrypt = 0,
            Encrypt = 1,
        };

        DES(scb::Bytes &&key);
        DES(scb::Bytes const &key);

        scb::Bytes decrypt1_ecb(scb::Bytes const &buffer) const;
        scb::Bytes encrypt1_ecb(scb::Bytes const &buffer) const;
        scb::Bytes decrypt1_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const;
        scb::Bytes encrypt1_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const;
        scb::Bytes crypt1(scb::Bytes const &buffer, Operation operation, scb::Bytes const &iv) const;

        scb::Bytes decrypt3_ecb(scb::Bytes const &buffer) const;
        scb::Bytes encrypt3_ecb(scb::Bytes const &buffer) const;
        scb::Bytes decrypt3_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const;
        scb::Bytes encrypt3_cbc(scb::Bytes const &buffer, scb::Bytes const &iv) const;
        scb::Bytes crypt3(scb::Bytes const &buffer, Operation operation, scb::Bytes const &iv) const;

        scb::Bytes const key;

    private:
        static void validate_mode(Mode mode);
        static void validate_operation(Operation operation);
        static void validate_alignment(scb::Bytes const &buffer);
    };

}
