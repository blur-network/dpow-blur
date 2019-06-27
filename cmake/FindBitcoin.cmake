find_path(BITCOIN_INCLUDE_DIR
    NAMES bitcoin/bitcoin.h
    PATHS external/bitcoin
    NO_DEFAULT_PATH
)

find_library(BITCOIN_LIBRARY
    NAMES bitcoin
    PATHS external/bitcoin
    NO_DEFAULT_PATH
)

