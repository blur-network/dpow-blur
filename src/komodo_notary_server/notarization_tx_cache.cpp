#include "notarization_tx_cache.h"
#include "common/command_line.h"
#include "notarization_tx_container.h"

namespace tools {

std::vector<wallet2::pending_tx> get_cached_ptx()
{
  std::vector<wallet2::pending_tx> ptx = ntz_ptx_cache.back();
  if (!ptx.empty())
    ntz_ptx_cache.pop_back();
  return ptx;
}

bool add_ptx_to_cache(std::vector<wallet2::pending_tx>& ptx)
{
  if (ptx.empty()) {
    MERROR("Error: attempted to add empty ptx vector to cache!");
    return false;
  } else {
    ntz_ptx_cache.push_back(ptx);
    return true;
  }
}

size_t get_ntz_cache_count()
{
  return ntz_ptx_cache.size();
}

}
