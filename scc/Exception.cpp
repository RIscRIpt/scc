#include "Exception.h"

#include <vector>

#include <openssl/err.h>

using namespace scc;

static bool __dummy__ = (ERR_load_CRYPTO_strings(), 0);

Exception::Exception(unsigned long errcode)
    : std::runtime_error(string_from_errcode(errcode))
    , errcode(errcode)
{}

std::string Exception::string_from_errcode(unsigned long errcode) {
    std::vector<char> error(1024);
    ERR_error_string(errcode, error.data());
    return error.data();
}
