#include "operation.h"

#include <stdexcept>

using namespace scc;

void operation::validate(Operation operation) {
    if (operation != Decrypt && operation != Encrypt)
        throw std::invalid_argument("invalid operation");
}
