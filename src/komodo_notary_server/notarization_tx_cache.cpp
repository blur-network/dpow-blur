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

std::pair<std::list<std::string>, std::string> get_cached_peer_ptx_pair()
{
  std::pair<std::list<std::string>,std::string> cache_entry;
  if (!peer_ptx_cache.empty())
    cache_entry = peer_ptx_cache.back();
  return cache_entry;
}  

std::vector<wallet2::pending_tx> get_cached_peer_ptx()
{
  std::pair<std::list<std::string>,std::string> cache_entry;
  if (!peer_ptx_cache.empty())
    cache_entry = peer_ptx_cache.back();
  std::list<std::string> ptx_list = cache_entry.first;
  std::string signers_index_str = cache_entry.second;
  std::vector<wallet2::pending_tx> ptx_vec;
  if (!ptx_list.empty()) {
    peer_ptx_cache.pop_back();
  }
  for (const auto& each : ptx_list) {
    std::stringstream ss;
    ss << each;
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

bool add_peer_ptx_to_cache(std::list<std::string>& ptx_strings, std::string const& signers_index_str)
{
  std::pair<std::list<std::string>,std::string> cache_entry;
  cache_entry = std::make_pair(ptx_strings, signers_index_str);
  if (ptx_strings.empty()) {
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
  std::list<std::string> ptx_strings = arg.ptx_strings;
  int const sig_count = arg.sig_count;
  std::vector<int> signers_index = arg.signers_index;
  std::string signers_index_s;
  std::string payment_id = arg.payment_id;
  std::string tx_blob = arg.tx_blob;

  int const neg = -1;
  int const count = 13 - std::count(signers_index.begin(), signers_index.end(), neg);
  for (int i = 0; i < 13; i++)
  {
    std::string each_ind = std::to_string(neg);
    int tmp = cryptonote::get_index<int>(i, arg.signers_index);
    if ((tmp < 10) && (tmp != neg)) {
      each_ind = "0" + std::to_string(tmp);
    } else { 
      each_ind = std::to_string(tmp);
    }
    signers_index_s += each_ind;
  }
    return add_peer_ptx_to_cache(ptx_strings, signers_index_str);
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
