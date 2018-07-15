#pragma once

#include <stdexcept>

namespace scc {

    class Exception : public std::runtime_error {
    public:
        Exception(unsigned long errcode);

        int const errcode;

        static std::string string_from_errcode(unsigned long errcode);
    };

}
