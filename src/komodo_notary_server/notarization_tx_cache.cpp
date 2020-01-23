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
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"

namespace tools {

std::vector<wallet2::pending_tx> get_cached_ptx()
{
  std::vector<wallet2::pending_tx> ptx = ntz_ptx_cache.back();
  if (!ptx.empty())
    ntz_ptx_cache.pop_back();
  return ptx;
}

std::pair<std::string, std::string> get_cached_peer_ptx_pair()
{
  std::pair<std::string,std::string> cache_entry;
  if (!peer_ptx_cache.empty())
    cache_entry = peer_ptx_cache.back();
  if (!cache_entry.first.empty() && !cache_entry.second.empty())
    peer_ptx_cache.pop_back();
  return cache_entry;
}

std::vector<wallet2::pending_tx> get_cached_peer_ptx()
{
  std::pair<std::string,std::string> cache_entry = get_cached_peer_ptx_pair();
  std::vector<wallet2::pending_tx> ptx_vec;
  std::string ptx_string = cache_entry.first;
  std::string signers_index_str = cache_entry.second;
  if (!ptx_string.empty()) {
    std::stringstream ss;
    ss << ptx_string;
    boost::archive::portable_binary_oarchive ar(ss);
    wallet2::pending_tx ptx;
    ar << ptx;
    ptx_vec.push_back(ptx);
  }
  return ptx_vec;
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
  return false;
}

/*bool add_peer_ptx_to_cache(std::vector<wallet2::pending_tx> const& ptx)
{
  if (ptx.empty()) {
    MERROR("Error: attempted to add empty ptx vector to cache!");
    return false;
  } else {
    peer_ptx_cache.push_back(ptx);
    return true;
  }
}
*/

bool add_peer_ptx_to_cache(std::string& ptx_string, std::string const& signers_index_str)
{
  std::pair<std::string,std::string> cache_entry;
  cache_entry = std::make_pair(ptx_string, signers_index_str);
  if (ptx_string.empty()) {
    MERROR("Error: attempted to add empty ptx string to cache!");
    return false;
  } else {
      peer_ptx_cache.push_back(cache_entry);
    if (peer_ptx_cache.empty()) {
      return false;
    } else {
      return true;
    }
  }
}
bool req_ntz_sig_to_cache(cryptonote::NOTIFY_REQUEST_NTZ_SIG::request& arg, std::string const& signers_index_str)
{
  std::string ptx_string = arg.ptx_string;
  int const sig_count = arg.sig_count;
  std::string signers_index_s = arg.signers_index;
  std::vector<int> signers_index;
  for (size_t i = 0; i < 10; i++) {
    int tmp = 0;
    tmp = std::stoi(signers_index_s.substr(i*2, 2), nullptr, 10);
    signers_index.push_back(tmp);
  }
  std::string payment_id = arg.payment_id;
  std::string tx_blob = arg.tx_blob;

  int const neg = -1;
  int const count = 10 - std::count(signers_index.begin(), signers_index.end(), neg);
  return add_peer_ptx_to_cache(ptx_string, signers_index_s);
}

size_t get_ntz_cache_count()
{
  return ntz_ptx_cache.size();
}

size_t get_peer_ptx_cache_count()
{
  return peer_ptx_cache.size();
}

}
