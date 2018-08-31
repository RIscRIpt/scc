#pragma once

namespace scc {
    class operation {
    public:
        enum Operation {
            Decrypt = 0,
            Encrypt = 1,
        };

        operation() = delete;

        static void validate(Operation operation);
    };

}
