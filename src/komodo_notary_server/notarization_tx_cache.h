#include "wallet/wallet2.h"

namespace tools {

std::vector<tools::wallet2::pending_tx> get_cached_ptx();
bool add_ptx_to_cache(std::vector<tools::wallet2::pending_tx>& ptx);
size_t get_ntz_cache_count();
}
