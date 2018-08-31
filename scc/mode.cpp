#include "mode.h"

#include <stdexcept>

using namespace scc;

void mode::validate(Mode mode) {
    if (mode != ECB && mode != CBC)
        throw std::invalid_argument("invalid mode");
}
