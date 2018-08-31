#pragma once

namespace scc {

    class mode {
    public:
        enum Mode {
            ECB,
            CBC,
        };

        mode() = delete;

        static void validate(Mode mode);
    };

}
