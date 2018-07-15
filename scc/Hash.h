#pragma once

#include <vector>

#include <scb/Bytes.h>

namespace scc {

    scb::Bytes SHA1(scb::Bytes const &buffer);
    scb::Bytes SHA224(scb::Bytes const &buffer);
    scb::Bytes SHA256(scb::Bytes const &buffer);
    scb::Bytes SHA384(scb::Bytes const &buffer);
    scb::Bytes SHA512(scb::Bytes const &buffer);

}
