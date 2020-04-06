/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                     *
 *                                                    *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at            *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                    *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                    *
 * Removal or modification of this copyright notice is prohibited.        *
 *                                                    *
 ******************************************************************************/

/****************************************************************************************
 * Parts of this file have been modified for compatibility with the Blur Network.
 * The copyright notice below applies to only those portions that have been changed.
 *
 * Copyright (c) Blur Network, 2018-2020
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ****************************************************************************************/

#ifndef KOMODO_NOTARIES_H
#define KOMODO_NOTARIES_H

#include <vector>
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "p2p/net_node.h"


#pragma once

struct sha256_vstate { uint64_t length; uint32_t state[8],curlen; uint8_t buf[64]; };

namespace cryptonote {
  bool get_notary_pubkeys(std::vector<std::pair<crypto::public_key,crypto::public_key>>& notary_pubkeys);
  bool get_notary_secret_viewkeys(std::vector<crypto::secret_key>& notary_viewkeys);

namespace komodo {

char const ASSETCHAINS_SYMBOL[5] = "BLUR";

class komodo_core
{
  public:

  komodo_core(cryptonote::core& cr, nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>& p2p);

  void vcalc_sha256(uint8_t hash[256 >> 3],uint8_t *src,int32_t len);
  bits256 bits256_doublesha256(uint8_t *data,int32_t datalen);
  int32_t komodo_chainactive_timestamp();
  bool komodo_chainactive(uint64_t &height, cryptonote::block &b);
  int32_t komodo_heightstamp(uint64_t height);
  void komodo_disconnect(uint64_t height,cryptonote::block block);
  int32_t komodo_notarized_height(uint64_t *prevMoMheightp, uint256 *hashp,uint256 *txidp);
  int32_t komodo_notarizeddata(uint64_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp);
  void komodo_notarized_update(uint64_t nHeight,uint64_t notarized_height,uint256 notarized_hash,uint256 notarized_desttxid,uint256 MoM,int32_t MoMdepth);
  int32_t komodo_checkpoint(int32_t *notarized_heightp, uint64_t nHeight, crypto::hash& hash);
  void komodo_voutupdate(int32_t txi,int32_t vout,uint8_t *scriptbuf,int32_t scriptlen,int32_t height,int32_t *specialtxp,int32_t *notarizedheightp,uint64_t value,int32_t notarized,uint64_t signedmask);
  void komodo_connectblock(uint64_t& height,cryptonote::block& b);
  int32_t komodo_init(BlockchainDB* db);
  int32_t komodo_notaries(uint8_t pubkeys[64][33],uint64_t height,uint64_t timestamp);
  private:
    cryptonote::core& m_core;
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>& m_p2p;
    bool check_core_ready();
    bool check_core_busy();

};


  int32_t komodo_init(BlockchainDB& db);
  struct notarized_checkpoint *komodo_npptr(uint64_t height);

} // namespace komodo

} // namespace cryptonote
#endif
