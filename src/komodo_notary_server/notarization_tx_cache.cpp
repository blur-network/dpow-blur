// Copyright (c) 2019-2020, Blur Network
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

std::vector<wallet2::pending_tx> get_cached_peer_ptx()
{
  std::vector<wallet2::pending_tx> ptx = peer_ptx_cache.back();
  if (!ptx.empty())
    peer_ptx_cache.pop_back();
  return ptx;
}

bool add_ptx_to_cache(std::vector<wallet2::pending_tx> const& ptx)
{
  if (ptx.empty()) {
    MERROR("Error: attempted to add empty ptx vector to cache!");
    return false;
  } else {
    ntz_ptx_cache.push_back(ptx);
    return true;
  }
}
bool add_peer_ptx_to_cache(std::vector<wallet2::pending_tx> const& ptx)
{
  if (ptx.empty()) {
    MERROR("Error: attempted to add empty ptx vector to cache!");
    return false;
  } else {
    peer_ptx_cache.push_back(ptx);
    return true;
  }
}
/*
bool add_peer_ptx_to_cache(std::string const& ptx_string)
{
  if (ptx_string.empty()) {
    MERROR("Error: attempted to add empty ptx string to cache!");
    return false;
  } else {
    try {
      std::vector<wallet2::pending_tx> peer_ptx_vec;
      wallet2::pending_tx peer_ptx;
      std::istringstream iss(ptx_string);
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> peer_ptx;
      peer_ptx_vec.push_back(peer_ptx);
      if (!peer_ptx_vec.empty())
        peer_ptx_cache.push_back(peer_ptx_vec);
    } catch (std::exception& e) {
      MERROR("Exception at add_peer_ptx_to_cache!");
      return false;
    }
    if (peer_ptx_cache.empty()) {
      return false;
    } else {
      return true;
    }
  }
}
*/
size_t get_ntz_cache_count()
{
  return ntz_ptx_cache.size();
}

size_t get_peer_ptx_cache_count()
{
  return peer_ptx_cache.size();
}

}
