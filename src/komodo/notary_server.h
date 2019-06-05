// Copyright (c) 2017-2018, The Masari Project
// Copyright (c) 2014-2018, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma  once

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <string>
#include "common/util.h"
#include "net/http_server_impl_base.h"
#include "wallet/wallet2.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.rpc"

namespace tools
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class notary_server: public epee::http_server_impl_base<notary_server>
  {
  public:
    typedef epee::net_utils::connection_context_base connection_context;

    static const char* tr(const char* str);

    notary_server();
    ~notary_server();

    bool init(const boost::program_options::variables_map *vm);
    bool run();
    void stop();
    void set_wallet(wallet2 *cr);
  private:
  
      CHAIN_HTTP_TO_MAP2(connection_context); //forward http requests to uri map\
  
    BEGIN_URI_MAP2()
      BEGIN_JSON_RPC_MAP("/json_rpc")
      END_JSON_RPC_MAP()
    END_URI_MAP2()
          
        
      bool not_open(epee::json_rpc::error& er);
      void handle_rpc_exception(const std::exception_ptr& e, epee::json_rpc::error& er, int default_error_code);

      template<typename Ts, typename Tu>
      bool fill_response(std::vector<tools::wallet2::pending_tx> &ptx_vector,
                bool get_tx_key, Ts& tx_key, Tu &amount, Tu &fee, std::string &multisig_txset, bool do_not_relay,
          Ts &tx_hash, bool get_tx_hex, Ts &tx_blob, bool get_tx_metadata, Ts &tx_metadata, epee::json_rpc::error &er);

      wallet2 *m_wallet;
      std::string m_notary_wallet_dir;
      tools::private_file rpc_login_file;
      std::atomic<bool> m_stop;
      bool m_trusted_daemon;
      const boost::program_options::variables_map *m_vm;
  };
}
