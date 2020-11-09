// Copyright (c) 2018-2020, Blur Network
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

#include "include_base_utils.h"
#include "string_tools.h"
#include "span.h"

using namespace epee;

#include "core_rpc_server.h"
#include "common/command_line.h"
#include "common/util.h"
#include "common/perf_timer.h"
#include "common/hex_str.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "misc_language.h"
#include "storages/http_abstract_invoke.h"
#include "crypto/hash.h"
#include "rpc/rpc_args.h"
#include "core_rpc_server_error_codes.h"
#include "p2p/net_node.h"
#include "version.h"
#include "cryptonote_core/komodo_notaries.h"
#include "blockchain_db/db_structs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon.rpc"

#define MAX_RESTRICTED_FAKE_OUTS_COUNT 40
#define MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT 5000



namespace
{
  void add_reason(std::string &reasons, const char *reason)
  {
    if (!reasons.empty())
      reasons += ", ";
    reasons += reason;
  }
}

namespace cryptonote
{

  namespace komodo {
    extern int32_t NUM_NPOINTS,last_NPOINTSi,NOTARIZED_HEIGHT,NOTARIZED_MOMDEPTH,KOMODO_NEEDPUBKEYS,NOTARIZED_PREVHEIGHT;
    extern uint256 NOTARIZED_HASH, NOTARIZED_MOM, NOTARIZED_DESTTXID;
  }

  //-----------------------------------------------------------------------------------
  void core_rpc_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_port);
    command_line::add_arg(desc, arg_rpc_restricted_bind_port);
    command_line::add_arg(desc, arg_restricted_rpc);
    command_line::add_arg(desc, arg_bootstrap_daemon_address);
    command_line::add_arg(desc, arg_bootstrap_daemon_login);
    cryptonote::rpc_args::init_options(desc);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::core_rpc_server(
      core& cr
    , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
    )
    : m_core(cr)
    , m_p2p(p2p)
  {}
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::init(
      const boost::program_options::variables_map& vm
      , const bool restricted
      , const network_type nettype
      , const std::string& port
    )
  {
    m_restricted = restricted;
    m_nettype = nettype;
    m_net_server.set_threads_prefix("RPC");

    auto rpc_config = cryptonote::rpc_args::process(vm);
    if (!rpc_config)
      return false;

    m_bootstrap_daemon_address = command_line::get_arg(vm, arg_bootstrap_daemon_address);
    if (!m_bootstrap_daemon_address.empty())
    {
      const std::string &bootstrap_daemon_login = command_line::get_arg(vm, arg_bootstrap_daemon_login);
      const auto loc = bootstrap_daemon_login.find(':');
      if (!bootstrap_daemon_login.empty() && loc != std::string::npos)
      {
        epee::net_utils::http::login login;
        login.username = bootstrap_daemon_login.substr(0, loc);
        login.password = bootstrap_daemon_login.substr(loc + 1);
        m_http_client.set_server(m_bootstrap_daemon_address, login, false);
      }
      else
      {
        m_http_client.set_server(m_bootstrap_daemon_address, boost::none, false);
      }
      m_should_use_bootstrap_daemon = true;
    }
    else
    {
      m_should_use_bootstrap_daemon = false;
    }
    m_was_bootstrap_ever_used = false;

    boost::optional<epee::net_utils::http::login> http_login{};

    if (rpc_config->login)
      http_login.emplace(std::move(rpc_config->login->username), std::move(rpc_config->login->password).password());

    auto rng = [](size_t len, uint8_t *ptr){ return crypto::rand(len, ptr); };
    return epee::http_server_impl_base<core_rpc_server, connection_context>::init(
      rng, std::move(port), std::move(rpc_config->bind_ip), std::move(rpc_config->access_control_origins), std::move(http_login)
    );
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::check_core_ready()
  {
    if(!m_p2p.get_payload_object().is_synchronized())
    {
      return false;
    }
    return true;
  }
#define CHECK_CORE_READY() do { if(!check_core_ready()){res.status =  CORE_RPC_STATUS_BUSY;return true;} } while(0)

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res)
  {
    PERF_TIMER(on_get_height);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_HEIGHT>(invoke_http_mode::JON, "/getheight", req, res, r))
      return r;

    res.height = m_core.get_current_blockchain_height();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res)
  {
    PERF_TIMER(on_get_info);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_INFO>(invoke_http_mode::JON, "/getinfo", req, res, r))
    {
      res.bootstrap_daemon_address = m_bootstrap_daemon_address;
      crypto::hash top_hash;
      m_core.get_blockchain_top(res.height_without_bootstrap, top_hash);
      ++res.height_without_bootstrap; // turn top block height into blockchain height
      res.was_bootstrap_ever_used = true;
      return r;
    }

    m_core.get_blockchain_storage().get_k_core().komodo_update(m_core);

    res.notarized = komodo::NOTARIZED_HEIGHT;
    std::vector<uint8_t> v_hash(komodo::NOTARIZED_HASH.begin(), komodo::NOTARIZED_HASH.begin()+32);
    std::vector<uint8_t> v_txid(komodo::NOTARIZED_DESTTXID.begin(), komodo::NOTARIZED_DESTTXID.begin()+32);
    std::vector<uint8_t> v_mom(komodo::NOTARIZED_MOM.begin(), komodo::NOTARIZED_MOM.begin()+32);

    res.notarizedhash = bytes256_to_hex(v_hash);
    res.notarizedtxid = bytes256_to_hex(v_txid);
    res.notarization_count = komodo::NUM_NPOINTS;
    res.notarized_MoM = bytes256_to_hex(v_mom);
    res.prevMoMheight = komodo::NOTARIZED_PREVHEIGHT;

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    res.blocks = res.height;
    ++res.height; // turn top block height into blockchain height
    res.top_block_hash = string_tools::pod_to_hex(top_hash);
    res.target_height = m_core.get_target_blockchain_height();
    res.difficulty = m_core.get_blockchain_storage().get_difficulty_for_next_block();
    res.target = m_core.get_blockchain_storage().get_difficulty_target();
    res.tx_count = m_core.get_blockchain_storage().get_total_transactions() - res.height; //without coinbase ----- TODO: This doesn't seem right
    res.tx_pool_size = m_core.get_pool_transactions_count();
    res.alt_blocks_count = m_core.get_blockchain_storage().get_alternative_blocks_count();
    uint64_t total_conn = m_p2p.get_connections_count();
    res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
    res.incoming_connections_count = total_conn - res.outgoing_connections_count;
    res.rpc_connections_count = get_connections_count();
    res.white_peerlist_size = m_p2p.get_peerlist_manager().get_white_peers_count();
    res.grey_peerlist_size = m_p2p.get_peerlist_manager().get_gray_peers_count();
    res.mainnet = m_nettype == MAINNET;
    res.testnet = m_nettype == TESTNET;
    res.stagenet = m_nettype == STAGENET;
    res.cumulative_difficulty = m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(res.height - 1);
    res.block_size_limit = m_core.get_blockchain_storage().get_current_cumulative_blocksize_limit();
    res.block_size_median = m_core.get_blockchain_storage().get_current_cumulative_blocksize_median();
    res.status = CORE_RPC_STATUS_OK;
    res.start_time = (uint64_t)m_core.get_start_time();
    res.free_space = m_restricted ? std::numeric_limits<uint64_t>::max() : m_core.get_free_space();
    res.offline = m_core.offline();
    res.bootstrap_daemon_address = m_bootstrap_daemon_address;
    res.height_without_bootstrap = res.height;
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      res.was_bootstrap_ever_used = m_was_bootstrap_ever_used;
    }
    res.version = MONERO_VERSION;
    return true;
  }
  //-----------------------------------------------------------------------------------------------------------------
  static cryptonote::blobdata get_pruned_tx_blob(cryptonote::transaction &tx)
  {
    std::stringstream ss;
    binary_archive<true> ba(ss);
    bool r = tx.serialize_base(ba);
    CHECK_AND_ASSERT_MES(r, cryptonote::blobdata(), "Failed to serialize rct signatures base");
    return ss.str();
  }
  //------------------------------------------------------------------------------------------------------------------
  static cryptonote::blobdata get_pruned_tx_blob(const cryptonote::blobdata &blobdata)
  {
    cryptonote::transaction tx;

    if (!cryptonote::parse_and_validate_tx_from_blob(blobdata, tx))
    {
      MERROR("Failed to parse and validate tx from blob");
      return cryptonote::blobdata();
    }

    return get_pruned_tx_blob(tx);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  static cryptonote::blobdata get_pruned_tx_json(cryptonote::transaction &tx)
  {
    std::stringstream ss;
    json_archive<true> ar(ss);
    bool r = tx.serialize_base(ar);
    CHECK_AND_ASSERT_MES(r, cryptonote::blobdata(), "Failed to serialize rct signatures base");
    return ss.str();
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res)
  {
    PERF_TIMER(on_get_blocks);

    std::list<std::pair<cryptonote::blobdata, std::list<cryptonote::blobdata> > > bs;

    if(!m_core.find_blockchain_supplement(req.start_height, req.block_ids, bs, res.current_height, res.start_height, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT))
    {
      res.status = "Failed";
      return false;
    }

    size_t pruned_size = 0, unpruned_size = 0, ntxes = 0;
    for(auto& bd: bs)
    {
      res.blocks.resize(res.blocks.size()+1);
      res.blocks.back().block = bd.first;
      pruned_size += bd.first.size();
      unpruned_size += bd.first.size();
      res.output_indices.push_back(COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices());
      res.output_indices.back().indices.push_back(COMMAND_RPC_GET_BLOCKS_FAST::tx_output_indices());
      block b;
      if (!parse_and_validate_block_from_blob(bd.first, b))
      {
        res.status = "Invalid block";
        return false;
      }
      bool r = m_core.get_tx_outputs_gindexs(get_transaction_hash(b.miner_tx), res.output_indices.back().indices.back().indices);
      if (!r)
      {
        res.status = "Failed";
        return false;
      }
      size_t txidx = 0;
      ntxes += bd.second.size();
      for (std::list<cryptonote::blobdata>::iterator i = bd.second.begin(); i != bd.second.end(); ++i)
      {
        unpruned_size += i->size();
        if (req.prune)
          res.blocks.back().txs.push_back(get_pruned_tx_blob(std::move(*i)));
        else
          res.blocks.back().txs.push_back(std::move(*i));
        i->clear();
        i->shrink_to_fit();
        pruned_size += res.blocks.back().txs.back().size();

        res.output_indices.back().indices.push_back(COMMAND_RPC_GET_BLOCKS_FAST::tx_output_indices());
        bool r = m_core.get_tx_outputs_gindexs(b.tx_hashes[txidx++], res.output_indices.back().indices.back().indices);
        if (!r)
        {
          res.status = "Failed";
          return false;
        }
      }
    }

    MDEBUG("on_get_blocks: " << bs.size() << " blocks, " << ntxes << " txes, pruned size " << pruned_size << ", unpruned size " << unpruned_size);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
    bool core_rpc_server::on_get_alt_blocks_hashes(const COMMAND_RPC_GET_ALT_BLOCKS_HASHES::request& req, COMMAND_RPC_GET_ALT_BLOCKS_HASHES::response& res)
    {
      PERF_TIMER(on_get_alt_blocks_hashes);
      bool r;
      if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_ALT_BLOCKS_HASHES>(invoke_http_mode::JON, "/get_alt_blocks_hashes", req, res, r))
        return r;

      std::list<block> blks;

      if(!m_core.get_alternative_blocks(blks))
      {
          res.status = "Failed";
          return false;
      }

      res.blks_hashes.reserve(blks.size());

      for (auto const& blk: blks)
      {
          res.blks_hashes.push_back(epee::string_tools::pod_to_hex(get_block_hash(blk)));
      }

      MDEBUG("on_get_alt_blocks_hashes: " << blks.size() << " blocks " );
      res.status = CORE_RPC_STATUS_OK;
      return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks_by_height(const COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response& res)
  {
    PERF_TIMER(on_get_blocks_by_height);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCKS_BY_HEIGHT>(invoke_http_mode::BIN, "/getblocks_by_height.bin", req, res, r))
      return r;

    res.status = "Failed";
    res.blocks.clear();
    res.blocks.reserve(req.heights.size());
    for (uint64_t height : req.heights)
    {
      block blk;
      try
      {
        blk = m_core.get_blockchain_storage().get_db().get_block_from_height(height);
      }
      catch (...)
      {
        res.status = "Error retrieving block at height " + std::to_string(height);
        return true;
      }
      std::list<transaction> txs;
      std::list<crypto::hash> missed_txs;
      m_core.get_transactions(blk.tx_hashes, txs, missed_txs);
      res.blocks.resize(res.blocks.size() + 1);
      res.blocks.back().block = block_to_blob(blk);
      for (auto& tx : txs)
        res.blocks.back().txs.push_back(tx_to_blob(tx));
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_hashes(const COMMAND_RPC_GET_HASHES_FAST::request& req, COMMAND_RPC_GET_HASHES_FAST::response& res)
  {
    PERF_TIMER(on_get_hashes);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_HASHES_FAST>(invoke_http_mode::BIN, "/gethashes.bin", req, res, r))
      return r;

    NOTIFY_RESPONSE_CHAIN_ENTRY::request resp;

    resp.start_height = req.start_height;
    if(!m_core.find_blockchain_supplement(req.block_ids, resp))
    {
      res.status = "Failed";
      return false;
    }
    res.current_height = resp.total_height;
    res.start_height = resp.start_height;
    res.m_block_ids = std::move(resp.m_block_ids);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res)
  {
    PERF_TIMER(on_get_random_outs);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(invoke_http_mode::BIN, "/getrandom_outs.bin", req, res, r))
      return r;

    res.status = "Failed";

    if (m_restricted)
    {
      if (req.amounts.size() > 100 || req.outs_count > MAX_RESTRICTED_FAKE_OUTS_COUNT)
      {
        res.status = "Too many outs requested";
        return true;
      }
    }

    if(!m_core.get_random_outs_for_amounts(req, res))
    {
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    std::stringstream ss;
    typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
    typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;
    std::for_each(res.outs.begin(), res.outs.end(), [&](outs_for_amount& ofa)
    {
      ss << "[" << ofa.amount << "]:";
      CHECK_AND_ASSERT_MES(ofa.outs.size(), ;, "internal error: ofa.outs.size() is empty for amount " << ofa.amount);
      std::for_each(ofa.outs.begin(), ofa.outs.end(), [&](out_entry& oe)
          {
            ss << oe.global_amount_index << " ";
          });
      ss << ENDL;
    });
    std::string s = ss.str();
    LOG_PRINT_L2("COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS: " << ENDL << s);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_outs_bin(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res)
  {
    PERF_TIMER(on_get_outs_bin);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_OUTPUTS_BIN>(invoke_http_mode::BIN, "/get_outs.bin", req, res, r))
      return r;

    res.status = "Failed";

    if (m_restricted)
    {
      if (req.outputs.size() > MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT)
      {
        res.status = "Too many outs requested";
        return true;
      }
    }

    if(!m_core.get_outs(req, res))
    {
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_best_block_hash(const COMMAND_RPC_GET_BEST_BLOCK_HASH::request& req, COMMAND_RPC_GET_BEST_BLOCK_HASH::response& res)
  {

    res.status = "Failed";

    const crypto::hash bestblockhash = m_core.get_blockchain_storage().get_best_block_hash();

    if (epee::string_tools::pod_to_hex(bestblockhash) == epee::string_tools::pod_to_hex(crypto::null_hash))
    {
      return false;
    }

    res.hex = epee::string_tools::pod_to_hex(bestblockhash);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_outs(const COMMAND_RPC_GET_OUTPUTS::request& req, COMMAND_RPC_GET_OUTPUTS::response& res)
  {
    PERF_TIMER(on_get_outs);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_OUTPUTS>(invoke_http_mode::JON, "/get_outs", req, res, r))
      return r;

    res.status = "Failed";

    if (m_restricted)
    {
      if (req.outputs.size() > MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT)
      {
        res.status = "Too many outs requested";
        return true;
      }
    }

    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req_bin;
    req_bin.outputs = req.outputs;
    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response res_bin;
    if(!m_core.get_outs(req_bin, res_bin))
    {
      return true;
    }

    // convert to text
    for (const auto &i: res_bin.outs)
    {
      res.outs.push_back(cryptonote::COMMAND_RPC_GET_OUTPUTS::outkey());
      cryptonote::COMMAND_RPC_GET_OUTPUTS::outkey &outkey = res.outs.back();
      outkey.key = epee::string_tools::pod_to_hex(i.key);
      outkey.mask = epee::string_tools::pod_to_hex(i.mask);
      outkey.unlocked = i.unlocked;
      outkey.height = i.height;
      outkey.txid = epee::string_tools::pod_to_hex(i.txid);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_random_rct_outs(const COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::request& req, COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::response& res)
  {
    PERF_TIMER(on_get_random_rct_outs);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS>(invoke_http_mode::BIN, "/getrandom_rctouts.bin", req, res, r))
      return r;

    res.status = "Failed";
    if(!m_core.get_random_rct_outs(req, res))
    {
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    std::stringstream ss;
    typedef COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::out_entry out_entry;
    CHECK_AND_ASSERT_MES(res.outs.size(), true, "internal error: res.outs.size() is empty");
    std::for_each(res.outs.begin(), res.outs.end(), [&](out_entry& oe)
      {
        ss << oe.global_amount_index << " ";
      });
    ss << ENDL;
    std::string s = ss.str();
    LOG_PRINT_L2("COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS: " << ENDL << s);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res)
  {
    PERF_TIMER(on_get_indexes);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(invoke_http_mode::BIN, "/get_o_indexes.bin", req, res, ok))
      return ok;

    bool r = m_core.get_tx_outputs_gindexs(req.txid, res.o_indexes);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    LOG_PRINT_L2("COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << res.o_indexes.size() << "]");
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res)
  {
    PERF_TIMER(on_get_transactions);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTIONS>(invoke_http_mode::JON, "/gettransactions", req, res, ok))
      return ok;

    std::vector<crypto::hash> vh;
    for(const auto& tx_hex_str: req.txs_hashes)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(tx_hex_str, b))
      {
        res.status = "Failed to parse hex representation of transaction hash";
        return true;
      }
      if(b.size() != sizeof(crypto::hash))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      vh.push_back(*reinterpret_cast<const crypto::hash*>(b.data()));
    }
    std::list<crypto::hash> missed_txs;
    std::list<transaction> txs;
    bool r = m_core.get_transactions(vh, txs, missed_txs);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    LOG_PRINT_L2("Found " << txs.size() << "/" << vh.size() << " transactions on the blockchain");

    // try the pool for any missing txes
    size_t found_in_pool = 0;
    size_t found_in_ntzpool = 0;
    std::unordered_set<crypto::hash> pool_tx_hashes;
    std::unordered_map<crypto::hash, bool> double_spend_seen;
    if (!missed_txs.empty())
    {
      std::vector<tx_info> pool_tx_info;
      std::vector<spent_key_image_info> pool_key_image_info;
      bool r = m_core.get_pool_transactions_and_spent_keys_info(pool_tx_info, pool_key_image_info);
      if(r)
      {
        // sort to match original request
        std::vector<tx_info>::const_iterator i;
        std::list<transaction> sorted_txs;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.empty())
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (get_transaction_hash(txs.front()) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_txs.push_back(std::move(txs.front()));
            txs.pop_front();
          }
          else if ((i = std::find_if(pool_tx_info.begin(), pool_tx_info.end(), [h](const tx_info &txi) { return epee::string_tools::pod_to_hex(h) == txi.id_hash; })) != pool_tx_info.end())
          {
            cryptonote::transaction tx;
            if (!cryptonote::parse_and_validate_tx_from_blob(i->tx_blob, tx))
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
            sorted_txs.push_back(tx);
            missed_txs.remove(h);
            pool_tx_hashes.insert(h);
            const std::string hash_string = epee::string_tools::pod_to_hex(h);
            for (const auto &ti: pool_tx_info)
            {
              if (ti.id_hash == hash_string)
              {
                double_spend_seen.insert(std::make_pair(h, ti.double_spend_seen));
                break;
              }
            }
            ++found_in_pool;
          }
        }
      }
      LOG_PRINT_L2("Found " << found_in_pool << "/" << vh.size() << " transactions in the txpool");
    }

    std::list<std::string>::const_iterator txhi = req.txs_hashes.begin();
    std::vector<crypto::hash>::const_iterator vhi = vh.begin();
    for(auto& tx: txs)
    {
      res.txs.push_back(COMMAND_RPC_GET_TRANSACTIONS::entry());
      COMMAND_RPC_GET_TRANSACTIONS::entry &e = res.txs.back();

      crypto::hash tx_hash = *vhi++;
      e.tx_hash = *txhi++;
      blobdata blob = req.prune ? get_pruned_tx_blob(tx) : t_serializable_object_to_blob(tx);
      e.as_hex = string_tools::buff_to_hex_nodelimer(blob);
      if (req.decode_as_json)
        e.as_json = req.prune ? get_pruned_tx_json(tx) : obj_to_json_str(tx);
      e.in_pool = pool_tx_hashes.find(tx_hash) != pool_tx_hashes.end();
      if (e.in_pool)
      {
        e.block_height = e.block_timestamp = std::numeric_limits<uint64_t>::max();
        if (double_spend_seen.find(tx_hash) != double_spend_seen.end())
        {
          e.double_spend_seen = double_spend_seen[tx_hash];
        }
        else
        {
          MERROR("Failed to determine double spend status for " << tx_hash);
          e.double_spend_seen = false;
        }
      }
      else
      {
        e.block_height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
        e.block_timestamp = m_core.get_blockchain_storage().get_db().get_block_timestamp(e.block_height);
        e.double_spend_seen = false;
      }

      // output indices too if not in pool
      if (pool_tx_hashes.find(tx_hash) == pool_tx_hashes.end())
      {
        bool r = m_core.get_tx_outputs_gindexs(tx_hash, e.output_indices);
        if (!r)
        {
          res.status = "Failed";
          return false;
        }
      }
    }

    for(const auto& miss_tx: missed_txs)
    {
      res.missed_tx.push_back(string_tools::pod_to_hex(miss_tx));
    }

    LOG_PRINT_L2(res.txs.size() << " transactions found, " << res.missed_tx.size() << " not found");
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
/*  bool core_rpc_server::on_get_notarizations(const COMMAND_RPC_GET_NOTARIZATIONS::request& req, COMMAND_RPC_GET_NOTARIZATIONS::response& res)
  {
    PERF_TIMER(on_get_transactions);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_NOTARIZATIONS>(invoke_http_mode::JON, "/get_notarizations", req, res, ok))
      return ok;

    std::vector<crypto::hash> vh;
    for(const auto& tx_hex_str: req.ntz_hashes)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(tx_hex_str, b))
      {
        res.status = "Failed to parse hex representation of transaction hash";
        return true;
      }
      if(b.size() != sizeof(crypto::hash))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      vh.push_back(*reinterpret_cast<const crypto::hash*>(b.data()));
    }
    std::list<crypto::hash> missed_txs;
    std::list<transaction> txs;
    for (const auto& each : vh) {
      cryptonote::transaction each_tx;
      bool r = m_core.get_blockchain_storage().get_db().get_ntz_tx(each, each_tx);
      if (!r) {
        missed_txs.push_back(get_transaction_hash(each_tx));
      } else {
        txs.push_back(each_tx);
      }
    }
    // try the pool for any missing txes
    size_t found_in_pool = 0;
    std::unordered_set<crypto::hash> pool_tx_hashes;
    std::unordered_map<crypto::hash, bool> double_spend_seen;
    if (!missed_txs.empty())
    {
      std::vector<tx_info> pool_tx_info;
      std::vector<spent_key_image_info> pool_key_image_info;
      bool r = m_core.get_pool_transactions_and_spent_keys_info(pool_tx_info, pool_key_image_info);
      if(r)
      {
        // sort to match original request
        std::vector<tx_info>::const_iterator i;
        std::list<transaction> sorted_txs;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.empty())
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (get_transaction_hash(txs.front()) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_txs.push_back(std::move(txs.front()));
            txs.pop_front();
          }
          else if ((i = std::find_if(pool_tx_info.begin(), pool_tx_info.end(), [h](const tx_info &txi) { return epee::string_tools::pod_to_hex(h) == txi.id_hash; })) != pool_tx_info.end())
          {
            cryptonote::transaction tx;
            if (!cryptonote::parse_and_validate_tx_from_blob(i->tx_blob, tx))
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
            sorted_txs.push_back(tx);
            missed_txs.remove(h);
            pool_tx_hashes.insert(h);
            const std::string hash_string = epee::string_tools::pod_to_hex(h);
            for (const auto &ti: pool_tx_info)
            {
              if (ti.id_hash == hash_string)
              {
                double_spend_seen.insert(std::make_pair(h, ti.double_spend_seen));
                break;
              }
            }
            ++found_in_pool;
          }
        }
      }
    }
    LOG_PRINT_L2("Found " << txs.size() << "/" << vh.size() << " transactions on the blockchain");

    std::list<std::string>::const_iterator txhi = req.ntz_hashes.begin();
    std::vector<crypto::hash>::const_iterator vhi = vh.begin();
    for(auto& tx: txs)
    {
      if (tx.version != 2) {

      } else {
        res.txs.push_back(COMMAND_RPC_GET_NOTARIZATIONS::entry());
        COMMAND_RPC_GET_NOTARIZATIONS::entry &e = res.txs.back();

        crypto::hash tx_hash = *vhi++;
        e.ntz_tx_hash = *txhi++;
        // TODO: Change below to grab an index, not count. Placeholder for now
        e.notarization_index = m_core.get_blockchain_storage().get_db().get_notarization_count();
        blobdata blob = t_serializable_object_to_blob(tx);
        e.as_hex = string_tools::buff_to_hex_nodelimer(blob);
        if (req.decode_as_json)
          e.as_json = obj_to_json_str(tx);
        e.in_pool = pool_tx_hashes.find(tx_hash) != pool_tx_hashes.end();
        if (e.in_pool)
        {
          e.block_height = e.block_timestamp = std::numeric_limits<uint64_t>::max();
          if (double_spend_seen.find(tx_hash) != double_spend_seen.end())
          {
            e.double_spend_seen = double_spend_seen[tx_hash];
          }
          else
          {
            MERROR("Failed to determine double spend status for " << tx_hash);
            e.double_spend_seen = false;
          }
        } else {
          e.block_height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
          e.block_timestamp = m_core.get_blockchain_storage().get_db().get_block_timestamp(e.block_height);
          e.double_spend_seen = false;
          bool r = m_core.get_tx_outputs_gindexs(tx_hash, e.output_indices);
          if (!r)
          {
              res.status = "Failed";
              return false;
          }
        }
      }
    }
    for(const auto& miss_tx: missed_txs)
    {
      res.missed_tx.push_back(string_tools::pod_to_hex(miss_tx));
    }

    LOG_PRINT_L2(res.txs.size() << " transactions found, " << res.missed_tx.size() << " not found");
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_notarizations(const COMMAND_RPC_GET_NOTARIZATIONS::request& req, COMMAND_RPC_GET_NOTARIZATIONS::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_transactions);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_NOTARIZATIONS>(invoke_http_mode::JON, "/get_notarizations", req, res, ok))
      return ok;

    std::vector<crypto::hash> vh;
    for(const auto& tx_hex_str: req.ntz_hashes)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(tx_hex_str, b))
      {
        res.status = "Failed to parse hex representation of transaction hash";
        return true;
      }
      if(b.size() != sizeof(crypto::hash))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      vh.push_back(*reinterpret_cast<const crypto::hash*>(b.data()));
    }
    std::list<crypto::hash> missed_txs;
    std::list<transaction> txs;
    for (const auto& each : vh) {
      cryptonote::transaction each_tx;
      bool r = m_core.get_blockchain_storage().get_db().get_ntz_tx(each, each_tx);
      if (!r) {
        missed_txs.push_back(get_transaction_hash(each_tx));
      } else {
        txs.push_back(each_tx);
      }
    }
    // try the pool for any missing txes
    size_t found_in_pool = 0;
    std::unordered_set<crypto::hash> pool_tx_hashes;
    std::unordered_map<crypto::hash, bool> double_spend_seen;
    if (!missed_txs.empty())
    {
      std::vector<tx_info> pool_tx_info;
      std::vector<spent_key_image_info> pool_key_image_info;
      bool r = m_core.get_pool_transactions_and_spent_keys_info(pool_tx_info, pool_key_image_info);
      if(r)
      {
        // sort to match original request
        std::vector<tx_info>::const_iterator i;
        std::list<transaction> sorted_txs;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.empty())
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (get_transaction_hash(txs.front()) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_txs.push_back(std::move(txs.front()));
            txs.pop_front();
          }
          else if ((i = std::find_if(pool_tx_info.begin(), pool_tx_info.end(), [h](const tx_info &txi) { return epee::string_tools::pod_to_hex(h) == txi.id_hash; })) != pool_tx_info.end())
          {
            cryptonote::transaction tx;
            if (!cryptonote::parse_and_validate_tx_from_blob(i->tx_blob, tx))
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
            sorted_txs.push_back(tx);
            missed_txs.remove(h);
            pool_tx_hashes.insert(h);
            const std::string hash_string = epee::string_tools::pod_to_hex(h);
            for (const auto &ti: pool_tx_info)
            {
              if (ti.id_hash == hash_string)
              {
                double_spend_seen.insert(std::make_pair(h, ti.double_spend_seen));
                break;
              }
            }
            ++found_in_pool;
          }
        }
      }
    }
    LOG_PRINT_L2("Found " << txs.size() << "/" << vh.size() << " transactions on the blockchain");

    std::list<std::string>::const_iterator txhi = req.ntz_hashes.begin();
    std::vector<crypto::hash>::const_iterator vhi = vh.begin();
    for(auto& tx: txs)
    {
      if (tx.version != 2) {

      } else {
        res.txs.push_back(COMMAND_RPC_GET_NOTARIZATIONS::entry());
        COMMAND_RPC_GET_NOTARIZATIONS::entry &e = res.txs.back();

        crypto::hash tx_hash = *vhi++;
        e.ntz_tx_hash = *txhi++;
        // TODO: Change below to grab an index, not count. Placeholder for now
        e.notarization_index = m_core.get_blockchain_storage().get_db().get_notarization_count();
        blobdata blob = t_serializable_object_to_blob(tx);
        e.as_hex = string_tools::buff_to_hex_nodelimer(blob);
        if (req.decode_as_json)
          e.as_json = obj_to_json_str(tx);
        e.in_pool = pool_tx_hashes.find(tx_hash) != pool_tx_hashes.end();
        if (e.in_pool)
        {
          e.block_height = e.block_timestamp = std::numeric_limits<uint64_t>::max();
          if (double_spend_seen.find(tx_hash) != double_spend_seen.end())
          {
            e.double_spend_seen = double_spend_seen[tx_hash];
          }
          else
          {
            MERROR("Failed to determine double spend status for " << tx_hash);
            e.double_spend_seen = false;
          }
        } else {
          e.block_height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
          e.block_timestamp = m_core.get_blockchain_storage().get_db().get_block_timestamp(e.block_height);
          e.double_spend_seen = false;
          bool r = m_core.get_tx_outputs_gindexs(tx_hash, e.output_indices);
          if (!r)
          {
              res.status = "Failed";
              return false;
          }
        }
      }
    }
    for(const auto& miss_tx: missed_txs)
    {
      res.missed_tx.push_back(string_tools::pod_to_hex(miss_tx));
    }

    LOG_PRINT_L2(res.txs.size() << " transactions found, " << res.missed_tx.size() << " not found");
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }*/
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transactions_by_heights(const COMMAND_RPC_GET_TRANSACTIONS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_TRANSACTIONS_BY_HEIGHTS::response& res)
  {
    PERF_TIMER(on_get_transactions_by_heights);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTIONS_BY_HEIGHTS>(invoke_http_mode::JON, "/gettransactions_by_heights", req, res, ok))
      return ok;

    std::vector<crypto::hash> vh;

    for (size_t i = 0; i < req.heights.size(); i++)
    {
      block blk;
      bool orphan = false;
      crypto::hash block_hash = m_core.get_block_id_by_height(req.heights[i]);
      bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);

      for(auto& btxs: blk.tx_hashes)
        vh.push_back(btxs);
    }

    std::list<crypto::hash> missed_txs;
    std::list<transaction> txs;
    bool r = m_core.get_transactions(vh, txs, missed_txs);

    std::list<std::string> tx_hashes;
    for(auto& tx: txs)
      tx_hashes.push_back(string_tools::pod_to_hex(get_transaction_hash(tx)));

    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    LOG_PRINT_L2("Found " << txs.size() << "/" << vh.size() << " transactions on the blockchain");

    // try the pool for any missing txes
    size_t found_in_pool = 0;
    size_t found_in_ntzpool = 0;
    std::unordered_set<crypto::hash> pool_tx_hashes;
    std::unordered_set<crypto::hash> ntzpool_tx_hashes;
    std::unordered_map<crypto::hash, bool> double_spend_seen;
    if (!missed_txs.empty())
    {
      std::vector<tx_info> pool_tx_info;
      std::vector<spent_key_image_info> pool_key_image_info;
      std::vector<ntz_tx_info> ntzpool_tx_info;
      std::vector<spent_key_image_info> ntzpool_key_image_info;
      bool r = m_core.get_pool_transactions_and_spent_keys_info(pool_tx_info, pool_key_image_info);
      bool R = m_core.get_pending_ntz_pool_and_spent_keys_info(ntzpool_tx_info, ntzpool_key_image_info);
      if(r)
      {
        // sort to match original request
        std::list<transaction> sorted_txs;
        std::vector<tx_info>::const_iterator i;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.empty())
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (get_transaction_hash(txs.front()) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_txs.push_back(std::move(txs.front()));
            txs.pop_front();
          }
          else if ((i = std::find_if(pool_tx_info.begin(), pool_tx_info.end(), [h](const tx_info &txi) { return epee::string_tools::pod_to_hex(h) == txi.id_hash; })) != pool_tx_info.end())
          {
            cryptonote::transaction tx;
            if (!cryptonote::parse_and_validate_tx_from_blob(i->tx_blob, tx))
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
            sorted_txs.push_back(tx);
            missed_txs.remove(h);
            pool_tx_hashes.insert(h);
            const std::string hash_string = epee::string_tools::pod_to_hex(h);
            for (const auto &ti: pool_tx_info)
            {
              if (ti.id_hash == hash_string)
              {
                double_spend_seen.insert(std::make_pair(h, ti.double_spend_seen));
                break;
              }
            }
            ++found_in_pool;
          }
        }
      }
      else if (R)
      {
        std::vector<ntz_tx_info>::const_iterator j;
        std::list<transaction> sorted_ntz_txs;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.empty())
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (get_transaction_hash(txs.front()) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_ntz_txs.push_back(std::move(txs.front()));
            txs.pop_front();
          }
          else if ((j = std::find_if(ntzpool_tx_info.begin(), ntzpool_tx_info.end(), [h](const ntz_tx_info &txi) { return epee::string_tools::pod_to_hex(h) == txi.id_hash; })) != ntzpool_tx_info.end())
          {
            cryptonote::transaction tx;
            if (!cryptonote::parse_and_validate_tx_from_blob(j->tx_blob, tx))
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
            sorted_ntz_txs.push_back(tx);
            missed_txs.remove(h);
            ntzpool_tx_hashes.insert(h);
            const std::string hash_string = epee::string_tools::pod_to_hex(h);
            for (const auto &ti: ntzpool_tx_info)
            {
              if (ti.id_hash == hash_string)
              {
                double_spend_seen.insert(std::make_pair(h, ti.double_spend_seen));
                break;
              }
            }
            ++found_in_ntzpool;
          }
        }
      }
      LOG_PRINT_L2("Found " << found_in_pool << "/" << vh.size() << " transactions in the txpool");
      LOG_PRINT_L2("Found " << found_in_pool << "/" << vh.size() << " transactions in the ntzpool");
    }

    std::list<std::string>::const_iterator txhi = tx_hashes.begin();
    std::vector<crypto::hash>::const_iterator vhi = vh.begin();
    for(auto& tx: txs)
    {
      res.txs.push_back(COMMAND_RPC_GET_TRANSACTIONS_BY_HEIGHTS::entry());
      COMMAND_RPC_GET_TRANSACTIONS_BY_HEIGHTS::entry &e = res.txs.back();

      crypto::hash tx_hash = *vhi++;
      e.tx_hash = *txhi++;
      blobdata blob = req.prune ? get_pruned_tx_blob(tx) : t_serializable_object_to_blob(tx);
      e.as_hex = string_tools::buff_to_hex_nodelimer(blob);
      if (req.decode_as_json)
        e.as_json = req.prune ? get_pruned_tx_json(tx) : obj_to_json_str(tx);
      e.in_pool = pool_tx_hashes.find(tx_hash) != pool_tx_hashes.end();
      if (e.in_pool)
      {
        e.block_height = e.block_timestamp = std::numeric_limits<uint64_t>::max();
        if (double_spend_seen.find(tx_hash) != double_spend_seen.end())
        {
          e.double_spend_seen = double_spend_seen[tx_hash];
        }
        else
        {
          MERROR("Failed to determine double spend status for " << tx_hash);
          e.double_spend_seen = false;
        }
      }
      else
      {
        e.block_height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
        e.block_timestamp = m_core.get_blockchain_storage().get_db().get_block_timestamp(e.block_height);
        e.double_spend_seen = false;
      }

      // output indices too if not in pool
      if (pool_tx_hashes.find(tx_hash) == pool_tx_hashes.end())
      {
        bool r = m_core.get_tx_outputs_gindexs(tx_hash, e.output_indices);
        if (!r)
        {
          res.status = "Failed";
          return false;
        }
      }
    }

    for(const auto& miss_tx: missed_txs)
    {
      res.missed_tx.push_back(string_tools::pod_to_hex(miss_tx));
    }

    LOG_PRINT_L2(res.txs.size() << " transactions found, " << res.missed_tx.size() << " not found");
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_is_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res, bool request_has_rpc_origin)
  {
    PERF_TIMER(on_is_key_image_spent);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_IS_KEY_IMAGE_SPENT>(invoke_http_mode::JON, "/is_key_image_spent", req, res, ok))
      return ok;

    std::vector<crypto::key_image> key_images;
    for(const auto& ki_hex_str: req.key_images)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(ki_hex_str, b))
      {
        res.status = "Failed to parse hex representation of key image";
        return true;
      }
      if(b.size() != sizeof(crypto::key_image))
      {
        res.status = "Failed, size of data mismatch";
      }
      key_images.push_back(*reinterpret_cast<const crypto::key_image*>(b.data()));
    }
    std::vector<bool> spent_status;
    bool r = m_core.are_key_images_spent(key_images, spent_status);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    res.spent_status.clear();
    for (size_t n = 0; n < spent_status.size(); ++n)
      res.spent_status.push_back(spent_status[n] ? COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_BLOCKCHAIN : COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT);

    // check the pool too
    std::vector<cryptonote::tx_info> txs;
    std::vector<cryptonote::ntz_tx_info> ntxs;
    std::vector<cryptonote::spent_key_image_info> ki;
    std::vector<cryptonote::spent_key_image_info> nki;
    r = m_core.get_pool_transactions_and_spent_keys_info(txs, ki, !request_has_rpc_origin || !m_restricted);
    bool R = m_core.get_pending_ntz_pool_and_spent_keys_info(ntxs, nki, !request_has_rpc_origin || !m_restricted);
    if(!r)
    {
      if (!R)
      {
        res.status = "Failed";
        return true;
      }
    }
    for (std::vector<cryptonote::spent_key_image_info>::const_iterator i = ki.begin(); i != ki.end(); ++i)
    {
      crypto::hash hash;
      crypto::key_image spent_key_image;
      if (parse_hash256(i->id_hash, hash))
      {
        memcpy(&spent_key_image, &hash, sizeof(hash)); // a bit dodgy, should be other parse functions somewhere
        for (size_t n = 0; n < res.spent_status.size(); ++n)
        {
          if (res.spent_status[n] == COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT)
          {
            if (key_images[n] == spent_key_image)
            {
              res.spent_status[n] = COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_POOL;
              break;
            }
          }
        }
      }
    }
    for (std::vector<cryptonote::spent_key_image_info>::const_iterator i = nki.begin(); i != nki.end(); ++i)
    {
      crypto::hash hash;
      crypto::key_image spent_key_image;
      if (parse_hash256(i->id_hash, hash))
      {
        memcpy(&spent_key_image, &hash, sizeof(hash)); // a bit dodgy, should be other parse functions somewhere
        for (size_t n = 0; n < res.spent_status.size(); ++n)
        {
          if (res.spent_status[n] == COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT)
          {
            if (key_images[n] == spent_key_image)
            {
              res.spent_status[n] = COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_POOL;
              break;
            }
          }
        }
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res)
  {
    PERF_TIMER(on_send_raw_tx);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_SEND_RAW_TX>(invoke_http_mode::JON, "/sendrawtransaction", req, res, ok))
      return ok;

    CHECK_CORE_READY();

    std::string tx_blob;
    if(!string_tools::parse_hexstr_to_binbuff(req.tx_as_hex, tx_blob))
    {
      LOG_PRINT_L0("[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex);
      res.status = "Failed";
      return true;
    }

    cryptonote_connection_context fake_context;
    tx_verification_context tvc = AUTO_VAL_INIT(tvc);
    if(!m_core.handle_incoming_tx(tx_blob, tvc, false, false, false) || tvc.m_verifivation_failed)
    {
      res.status = "Failed";
      res.reason = "";
      if ((res.low_mixin = tvc.m_low_mixin))
        add_reason(res.reason, "ring size too small");
      if ((res.double_spend = tvc.m_double_spend))
        add_reason(res.reason, "double spend");
      if ((res.invalid_input = tvc.m_invalid_input))
        add_reason(res.reason, "invalid input");
      if ((res.invalid_output = tvc.m_invalid_output))
        add_reason(res.reason, "invalid output");
      if ((res.too_big = tvc.m_too_big))
        add_reason(res.reason, "too big");
      if ((res.overspend = tvc.m_overspend))
        add_reason(res.reason, "overspend");
      if ((res.fee_too_low = tvc.m_fee_too_low))
        add_reason(res.reason, "fee too low");
      if ((res.not_rct = tvc.m_not_rct))
        add_reason(res.reason, "tx is not ringct");
      const std::string punctuation = res.reason.empty() ? "" : ": ";
      if (tvc.m_verifivation_failed)
      {
        LOG_PRINT_L0("[on_send_raw_tx]: tx verification failed" << punctuation << res.reason);
      }
      else
      {
        LOG_PRINT_L0("[on_send_raw_tx]: Failed to process tx" << punctuation << res.reason);
      }
      return true;
    }

    if(!tvc.m_should_be_relayed)
    {
      LOG_PRINT_L0("[on_send_raw_tx]: tx accepted, but not relayed");
      res.reason = "Not relayed";
      res.not_relayed = true;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    NOTIFY_NEW_TRANSACTIONS::request r;
    r.txs.push_back(tx_blob);
    m_core.get_protocol()->relay_transactions(r, fake_context);
    //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_request_ntz_sig(const COMMAND_RPC_REQUEST_NTZ_SIG::request& req, COMMAND_RPC_REQUEST_NTZ_SIG::response& res)
  {
    CHECK_CORE_READY();

    cryptonote_connection_context fake_context;
    ntz_req_verification_context tvc = AUTO_VAL_INIT(tvc);
    const int sig_count = req.sig_count;
    cryptonote::transaction tx;
    crypto::hash tx_hash, tx_prefix_hash;

    if (!parse_and_validate_tx_from_blob(req.tx_blob, tx, tx_hash, tx_prefix_hash)) {
      MERROR("In rpc: Error parsing tx from blob!");
      return false;
    }

    std::string hash_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.ptx_hash, hash_data))
    {
      MERROR("Failed in converting current ptx hash to binbuff!");
      return false;
    }
    const crypto::hash ptx_hash =  *reinterpret_cast<const crypto::hash*>(hash_data.data());

/*    MWARNING("In rpc: req.ptx_hash = " << req.ptx_hash);
    MWARNING("In rpc: req.tx_blob = " << req.tx_blob);
    MWARNING("In rpc: req.ptx_string = " << req.ptx_string);
*/

    bool rs = false;
    tvc.m_signers_index = req.signers_index;
    tvc.m_sig_count = req.sig_count;
    const std::string signers_index = req.signers_index;
    const cryptonote::blobdata ptx_string = req.ptx_string;
    std::list<int> signers_list;
    for (size_t i = 0; i < DPOW_SIG_COUNT; i++) {
      signers_list.push_back(std::stoi(signers_index.substr(i*2, 2), nullptr, 10));
    }
    int neg = -1;
    int count = DPOW_SIG_COUNT - std::count(signers_list.begin(), signers_list.end(), neg);

    if (count != req.sig_count) {
      MERROR("Error signature count check against signers index failed!");
      tvc.m_verifivation_failed = true;
      return false;
    }

    std::string prior_tx_hash_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.prior_tx_hash, prior_tx_hash_data))
    {
      MERROR("Failed in converting prior tx hash to binbuff!");
      return false;
    }
    const crypto::hash prior_tx_hash = *reinterpret_cast<const crypto::hash*>(prior_tx_hash_data.data());

    std::string prior_ptx_hash_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.prior_ptx_hash, prior_ptx_hash_data))
    {
      MERROR("Failed in converting prior ptx hash to binbuff!");
      return false;
    }
    const crypto::hash prior_ptx_hash =  *reinterpret_cast<const crypto::hash*>(prior_ptx_hash_data.data());

      rs = m_core.handle_incoming_ntz_sig(req.tx_blob, tx_hash, tvc, false, true, false, sig_count, req.signers_index, ptx_string, ptx_hash, prior_tx_hash, prior_ptx_hash);
      if (rs == false)
      {
        res.status = "Failed";
        res.reason = "";
        if ((res.low_mixin = tvc.m_low_mixin))
          add_reason(res.reason, "ring size too small");
        if ((res.double_spend = tvc.m_double_spend))
          add_reason(res.reason, "double spend");
        if ((res.invalid_input = tvc.m_invalid_input))
          add_reason(res.reason, "invalid input");
        if ((res.invalid_output = tvc.m_invalid_output))
          add_reason(res.reason, "invalid output");
        if ((res.too_big = tvc.m_too_big))
          add_reason(res.reason, "too big");
        if ((res.overspend = tvc.m_overspend))
          add_reason(res.reason, "overspend");
        if ((res.fee_too_low = tvc.m_fee_too_low))
          add_reason(res.reason, "fee too low");
        if ((res.not_rct = tvc.m_not_rct))
          add_reason(res.reason, "tx is not ringct");
        if ((res.sig_count != tvc.m_sig_count))
          add_reason(res.reason, "signature count mismatch");
        if ((tvc.m_sig_count > DPOW_SIG_COUNT))
          add_reason(res.reason, "too many signatures");
        // TODO :: add signers_index count compared to sig_count here.
        const std::string punctuation = res.reason.empty() ? "" : ": ";
        if (tvc.m_verifivation_failed)
        {
          MERROR("[on_request_ntz_sig]: tx verification failed" << punctuation << res.reason);
          return false;
        }
      }

    if ((req.sig_count < DPOW_SIG_COUNT) && (req.sig_count > 0))
    {
      NOTIFY_REQUEST_NTZ_SIG::request r;
      r.ptx_string = req.ptx_string;
      r.ptx_hash = ptx_hash;
      r.tx_blob = req.tx_blob;
      r.sig_count = req.sig_count;
      r.payment_id = req.payment_id;
      r.signers_index = req.signers_index;

//      MWARNING("Ptx string in RPC: " << r.ptx_string);
      m_core.get_protocol()->relay_request_ntz_sig(r, fake_context);
      MINFO("[RPC] relay_request_ntz_sig sent with sigs count: " << std::to_string(r.sig_count) << ", signers_index = " << signers_index << ", and payment id: " << req.payment_id);
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }
    else if (req.sig_count >= DPOW_SIG_COUNT)
    {
      NOTIFY_NEW_TRANSACTIONS::request r;
      std::list<blobdata> verified_tx_blobs;
      verified_tx_blobs.push_back(req.tx_blob);
      r.txs = verified_tx_blobs;

      cryptonote::tx_verification_context tvc;
      std::vector<cryptonote::tx_verification_context> tvc_vec;
      tvc_vec.push_back(tvc);
      if (!m_core.handle_incoming_txs(verified_tx_blobs, tvc_vec, false, true, false)) {
        MERROR("[RPC] Error in handling incoming txs, in request_ntz_sig!");
        return false;
      }
      m_core.get_protocol()->relay_transactions(r, fake_context);
      std::vector<cryptonote::rpc::tx_in_ntzpool> tx_info;
      cryptonote::rpc::key_images_with_tx_hashes key_image_info;
      if(!m_core.get_ntzpool_for_rpc(tx_info, key_image_info)) {
        MERROR("[RPC] Failed to get_ntzpool_for_rpc()!");
      }
      std::list<crypto::hash> hash_list;
      for (const auto& each : tx_info) {
        hash_list.push_back(each.tx_hash);
      }
      m_core.get_blockchain_storage().flush_ntz_txes_from_pool(hash_list);
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }
    else
    {
      res.status = "Failed.";
      return false;
    }
  }
//------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res)
  {
    PERF_TIMER(on_start_mining);
    CHECK_CORE_READY();
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_nettype, req.miner_address))
    {
      res.status = "Failed, wrong address";
      LOG_PRINT_L0(res.status);
      return true;
    }
    if (info.is_subaddress)
    {
      res.status = "Mining to subaddress isn't supported yet";
      LOG_PRINT_L0(res.status);
      return true;
    }

    unsigned int concurrency_count = boost::thread::hardware_concurrency() * 2;

    // if we couldn't detect threads, set it to a ridiculously high number
    if(concurrency_count == 0)
    {
      concurrency_count = 1;
    }

    boost::thread::attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);

    if(!m_core.get_miner().start(info.address, static_cast<size_t>(req.threads_count), attrs))
    {
      res.status = "Failed, mining not started";
      LOG_PRINT_L0(res.status);
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res)
  {
    PERF_TIMER(on_stop_mining);
    if(!m_core.get_miner().stop())
    {
      res.status = "Failed, mining not stopped";
      LOG_PRINT_L0(res.status);
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_mining_status(const COMMAND_RPC_MINING_STATUS::request& req, COMMAND_RPC_MINING_STATUS::response& res)
  {
    PERF_TIMER(on_mining_status);

    const miner& lMiner = m_core.get_miner();
    res.active = lMiner.is_mining();

    if ( lMiner.is_mining() ) {
      res.speed = lMiner.get_speed();
      res.threads_count = lMiner.get_threads_count();
      const account_public_address& lMiningAdr = lMiner.get_mining_address();
      res.address = get_account_address_as_str(m_nettype, false, lMiningAdr);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_save_bc(const COMMAND_RPC_SAVE_BC::request& req, COMMAND_RPC_SAVE_BC::response& res)
  {
    PERF_TIMER(on_save_bc);
    if( !m_core.get_blockchain_storage().store_blockchain() )
    {
      res.status = "Error while storing blockchain";
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res)
  {
    PERF_TIMER(on_get_peer_list);
    std::list<nodetool::peerlist_entry> white_list;
    std::list<nodetool::peerlist_entry> gray_list;
    m_p2p.get_peerlist_manager().get_peerlist_full(gray_list, white_list);


    for (auto & entry : white_list)
    {
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::ID)
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen);
      else
        res.white_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen);
    }

    for (auto & entry : gray_list)
    {
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::ID)
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen);
      else
        res.gray_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_hash_rate(const COMMAND_RPC_SET_LOG_HASH_RATE::request& req, COMMAND_RPC_SET_LOG_HASH_RATE::response& res)
  {
    PERF_TIMER(on_set_log_hash_rate);
    if(m_core.get_miner().is_mining())
    {
      m_core.get_miner().do_print_hashrate(req.visible);
      res.status = CORE_RPC_STATUS_OK;
    }
    else
    {
      res.status = CORE_RPC_STATUS_NOT_MINING;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_level(const COMMAND_RPC_SET_LOG_LEVEL::request& req, COMMAND_RPC_SET_LOG_LEVEL::response& res)
  {
    PERF_TIMER(on_set_log_level);
    if (req.level < 0 || req.level > 4)
    {
      res.status = "Error: log level not valid";
      return true;
    }
    mlog_set_log_level(req.level);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_categories(const COMMAND_RPC_SET_LOG_CATEGORIES::request& req, COMMAND_RPC_SET_LOG_CATEGORIES::response& res)
  {
    PERF_TIMER(on_set_log_categories);
    mlog_set_log(req.categories.c_str());
    res.categories = mlog_get_categories();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res, bool request_has_rpc_origin)
  {
    PERF_TIMER(on_get_transaction_pool);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL>(invoke_http_mode::JON, "/get_transaction_pool", req, res, r))
      return r;

    m_core.get_pool_transactions_and_spent_keys_info(res.transactions, res.spent_key_images, !request_has_rpc_origin || !m_restricted);

   /* if (req.json_only)
    {
      for(auto& tx: res.transactions)
      {
        tx.blob_size = 0;
        tx.tx_blob = "";
      }
    }*/
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_ntz_pool_count(const COMMAND_RPC_GET_PENDING_NTZ_POOL_COUNT::request& req, COMMAND_RPC_GET_PENDING_NTZ_POOL_COUNT::response& res, bool request_has_rpc_origin)
  {
    size_t count;
    bool r = m_core.get_ntzpool_tx_count(count, true);
    res.count = count;
    if (r) {
      res.status = CORE_RPC_STATUS_OK;
    }
    return r;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_remove_ntzpool_tx(const COMMAND_RPC_REMOVE_NTZPOOL_TX::request& req, COMMAND_RPC_REMOVE_NTZPOOL_TX::response& res, bool request_has_rpc_origin)
  {
    std::list<crypto::hash> hashes;
    hashes.push_back(req.tx_hash);
    bool rem = m_core.get_blockchain_storage().flush_ntz_txes_from_pool(hashes);
    return rem;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_pending_ntz_pool(const COMMAND_RPC_GET_PENDING_NTZ_POOL::request& req, COMMAND_RPC_GET_PENDING_NTZ_POOL::response& res, bool request_has_rpc_origin)
  {
    PERF_TIMER(on_get_pending_ntz_pool);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_PENDING_NTZ_POOL>(invoke_http_mode::JON, "/get_pending_ntz_pool", req, res, r))
      return r;

    m_core.get_pending_ntz_pool_and_spent_keys_info(res.transactions, res.spent_key_images, !request_has_rpc_origin || !m_restricted);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_hashes(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response& res, bool request_has_rpc_origin)
  {
    PERF_TIMER(on_get_transaction_pool_hashes);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL_HASHES>(invoke_http_mode::JON, "/get_transaction_pool_hashes.bin", req, res, r))
      return r;

    m_core.get_pool_transaction_hashes(res.tx_hashes, !request_has_rpc_origin || !m_restricted);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_pending_ntz_pool_hashes(const COMMAND_RPC_GET_PENDING_NTZ_POOL_HASHES::request& req, COMMAND_RPC_GET_PENDING_NTZ_POOL_HASHES::response& res, bool request_has_rpc_origin)
  {
    PERF_TIMER(on_get_transaction_pool_hashes);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_PENDING_NTZ_POOL_HASHES>(invoke_http_mode::JON, "/get_pending_ntz_pool_hashes.bin", req, res, r))
      return r;

    m_core.get_pending_ntz_pool_hashes(res.tx_hashes, !request_has_rpc_origin || !m_restricted);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks_json(const COMMAND_RPC_GET_BLOCKS_JSON::request& req, COMMAND_RPC_GET_BLOCKS_JSON::response& res, bool request_has_rpc_origin)
  {
    PERF_TIMER(on_get_blocks_json);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCKS_JSON>(invoke_http_mode::JON, "/get_blocks_json", req, res, r))
      return r;

    for (size_t i = 0; i < req.heights.size(); i++)
    {
      if(m_core.get_current_blockchain_height() <= req.heights[i])
      {
        LOG_ERROR("Requested block at height " << req.heights[i] << " which is greater than top block height " << m_core.get_current_blockchain_height() - 1);
        continue;
      }

      block blk;
      bool orphan = false;
      crypto::hash block_hash = m_core.get_block_id_by_height(req.heights[i]);
      if (!m_core.get_block_by_hash(block_hash, blk, &orphan))
      {
        LOG_ERROR("Block with hash " << block_hash << " not found in database");
      }

      res.blocks.push_back(obj_to_json_str(blk));
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_stats(const COMMAND_RPC_GET_TRANSACTION_POOL_STATS::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_STATS::response& res, bool request_has_rpc_origin)
  {
    PERF_TIMER(on_get_transaction_pool_stats);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL_STATS>(invoke_http_mode::JON, "/get_transaction_pool_stats", req, res, r))
      return r;

    m_core.get_pool_transaction_stats(res.pool_stats, !request_has_rpc_origin || !m_restricted);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_pending_ntz_pool_stats(const COMMAND_RPC_GET_PENDING_NTZ_POOL_STATS::request& req, COMMAND_RPC_GET_PENDING_NTZ_POOL_STATS::response& res, bool request_has_rpc_origin)
  {
    PERF_TIMER(on_get_pending_ntz_pool_stats);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_PENDING_NTZ_POOL_STATS>(invoke_http_mode::JON, "/get_pending_ntz_pool_stats", req, res, r))
      return r;

    m_core.get_pending_ntz_pool_stats(res.pool_stats, !request_has_rpc_origin || !m_restricted);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res)
  {
    PERF_TIMER(on_stop_daemon);
    // FIXME: replace back to original m_p2p.send_stop_signal() after
    // investigating why that isn't working quite right.
    m_p2p.send_stop_signal();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res)
  {
    PERF_TIMER(on_getblockcount);
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      if (m_should_use_bootstrap_daemon)
      {
        res.status = "This command is unsupported for bootstrap daemon";
        return false;
      }
    }
    res.count = m_core.get_current_blockchain_height();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_getblockhash);
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      if (m_should_use_bootstrap_daemon)
      {
        res = "This command is unsupported for bootstrap daemon";
        return false;
      }
    }
    if(req.size() != 1)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Wrong parameters, expected height";
      return false;
    }
    uint64_t h = req[0];
    if(m_core.get_current_blockchain_height() <= h)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = std::string("Requested block height: ") + std::to_string(h) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
    }
    res = string_tools::pod_to_hex(m_core.get_block_id_by_height(h));
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_hash(const COMMAND_RPC_GET_BLOCK_HASH::request& req, COMMAND_RPC_GET_BLOCK_HASH::response& res)
  {
    res.status = "Failed";
    if(m_core.get_current_blockchain_height() <= req.height)
    {
      res.status = std::string("Failed! Requested block height: ") + std::to_string(req.height) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
      res.hash = epee::string_tools::pod_to_hex(crypto::null_hash);
      return true;
    }
    res.hash = epee::string_tools::pod_to_hex(m_core.get_block_id_by_height(req.height));
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_validateaddress(const COMMAND_RPC_VALIDATE_ADDRESS::request& req, COMMAND_RPC_VALIDATE_ADDRESS::response& res)
  {
    res.address = req[0];
    res.scriptPubKey = "76a9140ba28b34ebd21d0b18e8753e71c2663c171bec9888ac";
    res.segid = 4;
    res.isscript = false;
    res.ismine = true;
    res.iswatchonly = false;
    res.isvalid = true;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_btc_get_block(const COMMAND_RPC_BTC_GET_BLOCK::request& req, COMMAND_RPC_BTC_GET_BLOCK::response& res)
  {
    std::string reqhash = req.blockhash;
    cryptonote::block b; crypto::hash blockhash = crypto::null_hash; crypto::hash tree_hash = crypto::null_hash;
    res.data = "null";

    if (reqhash.empty()) {
      res.status = "Error: input hash empty!";
      return true;
    }
    std::string binhash;
    if(!epee::string_tools::parse_hexstr_to_binbuff(reqhash, binhash)) {
      res.status = "Failed to parse hex representation of block hash. Hex = " + reqhash;
      return true;
    }

    blockhash = *reinterpret_cast<const crypto::hash*>(binhash.data());

    if(!m_core.get_blockchain_storage().get_block_by_hash(blockhash, b)) {
      res.status = "Failed to get block for hash = " + reqhash;
      return true;
    }

    res.tx.push_back(epee::string_tools::pod_to_hex(get_transaction_hash(b.miner_tx)));
    for (const auto& each : b.tx_hashes) {
      res.tx.push_back(epee::string_tools::pod_to_hex(each));
    }

    m_core.get_blockchain_storage().get_k_core().komodo_update(m_core);
    uint64_t height = get_block_height(b);

    res.rawconfirmations = (m_core.get_blockchain_storage().get_current_blockchain_height()) - height;
    res.confirmations = (komodo::NOTARIZED_HEIGHT >= (int32_t)(height)) ? res.rawconfirmations : 1;
    res.height = height;
    tree_hash = get_tx_tree_hash(b);
    res.merkleroot = epee::string_tools::pod_to_hex(tree_hash);
    res.hash = epee::string_tools::pod_to_hex(m_core.get_blockchain_storage().get_block_id_by_height(height));
    res.version = b.major_version;
    res.last_notarized_height = komodo::NOTARIZED_HEIGHT;
    res.chainwork = string_tools::pod_to_hex(get_block_longhash(b, height));
    res.time = b.timestamp;
    res.difficulty = m_core.get_blockchain_storage().block_difficulty(height);
    res.size = m_core.get_blockchain_storage().get_db().get_block_size(height);
    res.previousblockhash = epee::string_tools::pod_to_hex(m_core.get_blockchain_storage().get_tail_id(height));

    std::string blob = block_to_blob(b);
    res.data = epee::string_tools::buff_to_hex_nodelimer(blob);
    res.solution = epee::string_tools::buff_to_hex_nodelimer(blob);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_send_raw_btc_tx(const COMMAND_RPC_SEND_RAW_BTC_TX::request& req, COMMAND_RPC_SEND_RAW_BTC_TX::response& res)
  {
    std::string hexreq = req.hexstring;
    if (hexreq.empty()) {
      res.status = "Error: input hex empty!";
      res.hex = "null";
      return true;
    }

    std::string bintxdata;
    if (!epee::string_tools::parse_hexstr_to_binbuff(hexreq, bintxdata)) {
      res.status = "Error: failed to parse hexstr to binbuff in send_raw_btc_tx";
      res.hex = "null";
      return true;
    }

    uint8_t const* txdata = reinterpret_cast<uint8_t const*>(bintxdata.data());
    bits256 btc_hash = m_core.get_blockchain_storage().get_k_core().bits256_doublesha256(txdata, bintxdata.size());
    std::vector<uint8_t> bitscontainer;
    for (const auto& each : btc_hash.bytes) {
      bitscontainer.push_back(each);
    }
    std::string hex_output = bytes256_to_hex(bitscontainer);

    res.hex = hex_output;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_sign_raw_btc_tx(const COMMAND_RPC_SIGN_RAW_BTC_TX::request& req, COMMAND_RPC_SIGN_RAW_BTC_TX::response& res)
  {
/*    std::string hexstr = req.hexstring;
    if (hexstr.empty()) {
      res.status = "Error: input hexstring empty!";
      res.hex = "null";
      res.complete = false;
      return true;
    }*/

    res.hex = "010000000dd42b2132cc0f6bea63ad6e94015e5fd988ea0370c519fb04aa3c91afac1cc90a0100000048473044022037abbb3ced70a8cd9c2f5c5dea1f4484140aa189b8911bd76340941462ecd4cd0220646879ec97649d121c6d7bcd1714f5a5cbe050216249eea0d94a7029791a8c8c01ffffffff4f2cb08342da314fac56bb95a1b5bb8f7c7f9505026e7f065a8049a568f6bf0b060000004847304402200c8f0746c945c4b72c2115049be8ccd184971ded8f35ffb6557aa5c85823889502204f5a1f3c9484967d98284c7c4511c9c61345159462c2c070d6b45e0d8fc07cc601ffffffff6c70688f390a33b5b10892e0a889670637543563d1ee0e54c8643f80d57be4fe06000000484730440220627db25375a00b939105a7afd0cacf20877d5dfc4d9205e27ab6ba189bdb3f5402201d5969f6ca779838d62c07f8d9c54ff940fe4eb5efc5847ceb4877ec02e1980801ffffffffbe5ff4358913fb0f357cd4f209eccfad53125dd0ed3c50a59c3811c9057ceb430600000049483045022100f452d8a6c70003c930d82f2540851ca18e83beb10a615bd4cc191b9e9df7d81902202457380fdfa79a8ce047ce7bf714d4f8dc1a2c4c9ab6d2a946b05ec6ad57af6f01ffffffff06f2556fe6339b4cd8fcb89b5d180ea1f83d1ebbf773a4fa97ae5aaa4e67cd60050000004847304402203a3fa35b169d7d1b23c63bf16d934e87154b3acdf43bffdeea9bcd711528c06202200592932c1882f19d97cf83bfc40453c5fe4bd91b0bc38f6068421546ba0b38a501ffffffff84a1ab93a653f5c5b005dafb66f04a0e141861d1d119f6373a0df5568ae3e32d030000004948304502210092d29c1689ff36acb43a6b9838820b4424449287e1eea8a2f591d8f9b9f59a89022063b9e87612a1b7489e4b50d9aed00c9c6373cc7abf041280561850c1b292756d01ffffffffb050ff20ccdbdc700cf3187ebe55d2d9919757638d5e1fa384bc36aaddc29a87000000004847304402200214c129a4182e9ffe71e627315e1dce1b660c49b5004652e7b230a4acc95b9e02204b6f66e0346b587a997b0f8571ca54641ca7995d60aef0a2ebdd353b8367958301ffffffff511bf19814deef29ee88b7a94cc936ae0981319df64605b4ff437746daca7f510900000049483045022100808b3bd26a837ee410e69ceb55b7b29e92833ee449467ca4b2922f5195028f3d022011680ccd601451667ba12ed9443124dc565ab67094aa2cf3d0cc0c67560ce0de01ffffffffb67bdcb7c7f7bc1279cfd085d44635ae7011fd529b1d549327d5ff731ff8fbd607000000484730440220379be20435df02115bedd84f1c5ef0c3b1a09f759e63c437e5879ab808bbc60a022009323b553e6fa48f4f56ea3c581549d7179a6b3d2b46f973d939d5cea6c1613701ffffffff6732d747a48663467d21c4282fb6705f3916421912ec4312ccf3cc6258933e35040000004847304402206f0e939e09a0ccb4d746663e15091aaa5ea64699b8f2faa515c079f41a0f2b4c02204dc5d887f6fc70c6488c644e6adc7e749fd0cbb5195eb986704e486a8a31ec3101ffffffff611904eeb777c1f1c86262fa7f8e3191a2125ee4c8440837e5b8604144dcb526090000004847304402206ec15a69e81569b606b550a7af9530172923c6933a6832608d8fb8f8cf9067ba0220136f0aaa4790e9120da876fa2cfa963b96d2774026c0f803d0924a6cefbf3d0e01fffffffff0300247cd2234bcffd923895b579cf7fbcba5405df5f09c468da835cc416e9005000000484730440220119ee524eae3810da16132e1e9aeb28f23ad81780389808124897f4ebfbacee302205204643fbccbd8befb5d1b71dbcca4a44b6ef0b32fcc894b3fed76ccfc6bd7c601ffffffffa377c825ea5a03dc93c93a41ac06f58042512d5098333574d6de0d8a6d5b99820700000049483045022100ad752b6d0ab189bc1a267008816d8cac4982823dc20a60967a078dc9ed17348e022066c4779c21f706ee3c4aa0f956e0d2a746c2cfb587550c07c5a6a2385c1f3ebf01ffffffff02b0890700000000002321020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9ac00000000000000002a6a28071c4524afe8cf8e412b6fdb06e65795839f189205119294d26939c61c37880a084409004b4d440000000000";
    res.complete = true;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_listunspent(const COMMAND_RPC_LIST_UNSPENT::request& req, COMMAND_RPC_LIST_UNSPENT::response& res)
  {
    std::list<std::string> addrs = req.addresses;
    for (const auto& each : addrs) {
      COMMAND_RPC_LIST_UNSPENT::unspent_entry e;
      e.address = each;
      e.scriptPubKey = "76a9140ba28b34ebd21d0b18e8753e71c2663c171bec9888ac";
      e.txid = epee::string_tools::pod_to_hex(m_core.get_blockchain_storage().get_tail_id());
      e.vout = 1;
      e.amount = 10000;
      e.confirmations = 1000;
      e.redeemScript = "76a9140ba28b34ebd21d0b18e8753e71c2663c171bec9888ac";
      e.spendable = true;
      e.solvable = true;
      e.safe = true;
      res.entries.push_back(e);
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // equivalent of strstr, but with arbitrary bytes (ie, NULs)
  // This does not differentiate between "not found" and "found at offset 0"
  uint64_t slow_memmem(const void* start_buff, size_t buflen,const void* pat,size_t patlen)
  {
    const void* buf = start_buff;
    const void* end=(const char*)buf+buflen;
    if (patlen > buflen || patlen == 0) return 0;
    while(buflen>0 && (buf=memchr(buf,((const char*)pat)[0],buflen-patlen+1)))
    {
      if(memcmp(buf,pat,patlen)==0)
        return (const char*)buf - (const char*)start_buff;
      buf=(const char*)buf+1;
      buflen = (const char*)end - (const char*)buf;
    }
    return 0;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_getblocktemplate);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GETBLOCKTEMPLATE>(invoke_http_mode::JON_RPC, "getblocktemplate", req, res, r))
      return r;

    if(!check_core_ready())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_CORE_BUSY;
      error_resp.message = "Core is busy";
      return false;
    }

    if(req.reserve_size > 255)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE;
      error_resp.message = "Too big reserved size, maximum 255";
      return false;
    }

    cryptonote::address_parse_info info;

    if(!req.wallet_address.size() || !cryptonote::get_account_address_from_str(info, m_nettype, req.wallet_address))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS;
      error_resp.message = "Failed to parse wallet address";
      return false;
    }
    if (info.is_subaddress)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_MINING_TO_SUBADDRESS;
      error_resp.message = "Mining to subaddress is not supported yet";
      return false;
    }

    block b = AUTO_VAL_INIT(b);
    cryptonote::blobdata blob_reserve;
    blob_reserve.resize(req.reserve_size, 0);
    if(!m_core.get_block_template(b, info.address, res.difficulty, res.height, res.expected_reward, blob_reserve))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to create block template");
      return false;
    }
    blobdata block_blob = t_serializable_object_to_blob(b);
    crypto::public_key tx_pub_key = cryptonote::get_tx_pub_key_from_extra(b.miner_tx);
    if(tx_pub_key == crypto::null_pkey)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to  tx pub key in coinbase extra");
      return false;
    }
    res.reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if(!res.reserved_offset)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to find tx pub key in blockblob");
      return false;
    }
    res.reserved_offset += sizeof(tx_pub_key) + 2; //2 bytes: tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if(res.reserved_offset + req.reserve_size > block_blob.size())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to calculate tx pub key reserved offset");
      return false;
    }
    blobdata hashing_blob = get_block_hashing_blob(b);
    res.prev_hash = string_tools::pod_to_hex(b.prev_id);
    res.blocktemplate_blob = string_tools::buff_to_hex_nodelimer(block_blob);
    res.blockhashing_blob =  string_tools::buff_to_hex_nodelimer(hashing_blob);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_submitblock);
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      if (m_should_use_bootstrap_daemon)
      {
        res.status = "This command is unsupported for bootstrap daemon";
        return false;
      }
    }
    CHECK_CORE_READY();
    if(req.size()!=1)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Wrong param";
      return false;
    }
    blobdata blockblob;
    if(!string_tools::parse_hexstr_to_binbuff(req[0], blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong block blob";
      return false;
    }

    // Fixing of high orphan issue for most pools
    // Thanks Boolberry!
    block b = AUTO_VAL_INIT(b);
    if(!parse_and_validate_block_from_blob(blockblob, b))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong block blob";
      return false;
    }

    // Fix from Boolberry neglects to check block
    // size, do that with the function below
    if(!m_core.check_incoming_block_size(blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE;
      error_resp.message = "Block bloc size is too big, rejecting block";
      return false;
    }

    if(!m_core.handle_block_found(b))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED;
      error_resp.message = "Block not accepted";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  uint64_t core_rpc_server::get_block_reward(const block& blk)
  {
    uint64_t reward = 0;
    for(const tx_out& out: blk.miner_tx.vout)
    {
      reward += out.amount;
    }
    return reward;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response)
  {
    PERF_TIMER(fill_block_header_response);
    response.major_version = blk.major_version;
    response.minor_version = blk.minor_version;
    response.timestamp = blk.timestamp;
    response.prev_hash = string_tools::pod_to_hex(blk.prev_id);
    response.nonce = blk.nonce;
    response.orphan_status = orphan_status;
    response.height = height;
    response.depth = m_core.get_current_blockchain_height() - height - 1;
    response.hash = string_tools::pod_to_hex(hash);
    response.difficulty = m_core.get_blockchain_storage().block_difficulty(height);
    response.reward = get_block_reward(blk);
    response.block_size = m_core.get_blockchain_storage().get_db().get_block_size(height);
    response.num_txes = blk.tx_hashes.size();
    response.pow_hash = string_tools::pod_to_hex(get_block_longhash(blk, height));
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template <typename COMMAND_TYPE>
  bool core_rpc_server::use_bootstrap_daemon_if_necessary(const invoke_http_mode &mode, const std::string &command_name, const typename COMMAND_TYPE::request& req, typename COMMAND_TYPE::response& res, bool &r)
  {
    res.untrusted = false;
    if (m_bootstrap_daemon_address.empty())
      return false;

    boost::unique_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
    if (!m_should_use_bootstrap_daemon)
    {
      MINFO("The local daemon is fully synced. Not switching back to the bootstrap daemon");
      return false;
    }

    auto current_time = std::chrono::system_clock::now();
    if (current_time - m_bootstrap_height_check_time > std::chrono::seconds(30))  // update every 30s
    {
      m_bootstrap_height_check_time = current_time;

      uint64_t top_height;
      crypto::hash top_hash;
      m_core.get_blockchain_top(top_height, top_hash);
      ++top_height; // turn top block height into blockchain height

      // query bootstrap daemon's height
      cryptonote::COMMAND_RPC_GET_HEIGHT::request getheight_req;
      cryptonote::COMMAND_RPC_GET_HEIGHT::response getheight_res;
      bool ok = epee::net_utils::invoke_http_json("/getheight", getheight_req, getheight_res, m_http_client);
      ok = ok && getheight_res.status == CORE_RPC_STATUS_OK;

      m_should_use_bootstrap_daemon = ok && top_height + 10 < getheight_res.height;
      MINFO((m_should_use_bootstrap_daemon ? "Using" : "Not using") << " the bootstrap daemon (our height: " << top_height << ", bootstrap daemon's height: " << getheight_res.height << ")");
    }
    if (!m_should_use_bootstrap_daemon)
      return false;

    if (mode == invoke_http_mode::JON)
    {
      r = epee::net_utils::invoke_http_json(command_name, req, res, m_http_client);
    }
    else if (mode == invoke_http_mode::BIN)
    {
      r = epee::net_utils::invoke_http_bin(command_name, req, res, m_http_client);
    }
    else if (mode == invoke_http_mode::JON_RPC)
    {
      epee::json_rpc::request<typename COMMAND_TYPE::request> json_req = AUTO_VAL_INIT(json_req);
      epee::json_rpc::response<typename COMMAND_TYPE::response, std::string> json_resp = AUTO_VAL_INIT(json_resp);
      json_req.jsonrpc = "2.0";
      json_req.id = epee::serialization::storage_entry(0);
      json_req.method = command_name;
      json_req.params = req;
      r = net_utils::invoke_http_json("/json_rpc", json_req, json_resp, m_http_client);
      if (r)
        res = json_resp.result;
    }
    else
    {
      MERROR("Unknown invoke_http_mode: " << mode);
      return false;
    }
    m_was_bootstrap_ever_used = true;
    r = r && res.status == CORE_RPC_STATUS_OK;
    res.untrusted = true;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_last_block_header);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_LAST_BLOCK_HEADER>(invoke_http_mode::JON_RPC, "getlastblockheader", req, res, r))
      return r;

    CHECK_CORE_READY();
    uint64_t last_block_height;
    crypto::hash last_block_hash;
    m_core.get_blockchain_top(last_block_height, last_block_hash);
    block last_block;
    bool have_last_block = m_core.get_block_by_hash(last_block_hash, last_block);
    if (!have_last_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get last block.";
      return false;
    }
    bool response_filled = fill_block_header_response(last_block, false, last_block_height, last_block_hash, res.block_header);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res, epee::json_rpc::error& error_resp){
    PERF_TIMER(on_get_block_header_by_hash);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH>(invoke_http_mode::JON_RPC, "getblockheaderbyhash", req, res, r))
      return r;

    crypto::hash block_hash;
    bool hash_parsed = parse_hash256(req.hash, block_hash);
    if(!hash_parsed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Failed to parse hex representation of block hash. Hex = " + req.hash + '.';
      return false;
    }
    block blk;
    bool orphan = false;
    bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by hash. Hash = " + req.hash + '.';
      return false;
    }
    if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
      return false;
    }
    uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
    bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, res.block_header);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_headers_range(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, epee::json_rpc::error& error_resp){
    PERF_TIMER(on_get_block_headers_range);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCK_HEADERS_RANGE>(invoke_http_mode::JON_RPC, "getblockheadersrange", req, res, r))
      return r;

    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.start_height >= bc_height || req.end_height >= bc_height || req.start_height > req.end_height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = "Invalid start/end heights.";
      return false;
    }
    for (uint64_t h = req.start_height; h <= req.end_height; ++h)
    {
      crypto::hash block_hash = m_core.get_block_id_by_height(h);
      block blk;
      bool have_block = m_core.get_block_by_hash(block_hash, blk);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by height. Height = " + boost::lexical_cast<std::string>(h) + ". Hash = " + epee::string_tools::pod_to_hex(block_hash) + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
      if (block_height != h)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong height";
        return false;
      }
      res.headers.push_back(block_header_response());
      bool response_filled = fill_block_header_response(blk, false, block_height, block_hash, res.headers.back());
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res, epee::json_rpc::error& error_resp){
    PERF_TIMER(on_get_block_header_by_height);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT>(invoke_http_mode::JON_RPC, "getblockheaderbyheight", req, res, r))
      return r;

    if(m_core.get_current_blockchain_height() <= req.height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = std::string("Too big height: ") + std::to_string(req.height) + ", current blockchain height = " +  std::to_string(m_core.get_current_blockchain_height());
      return false;
    }
    crypto::hash block_hash = m_core.get_block_id_by_height(req.height);
    block blk;
    bool have_block = m_core.get_block_by_hash(block_hash, blk);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.';
      return false;
    }
    bool response_filled = fill_block_header_response(blk, false, req.height, block_hash, res.block_header);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res, epee::json_rpc::error& error_resp){
    PERF_TIMER(on_get_block);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCK>(invoke_http_mode::JON_RPC, "getblock", req, res, r))
      return r;

    crypto::hash block_hash;
    if (!req.hash.empty())
    {
      bool hash_parsed = parse_hash256(req.hash, block_hash);
      if(!hash_parsed)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Failed to parse hex representation of block hash. Hex = " + req.hash + '.';
        return false;
      }
    }
    else
    {
      if(m_core.get_current_blockchain_height() <= req.height)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
        error_resp.message = std::string("Too big height: ") + std::to_string(req.height) + ", current blockchain height = " +  std::to_string(m_core.get_current_blockchain_height());
        return false;
      }
      block_hash = m_core.get_block_id_by_height(req.height);
    }
    block blk;
    bool orphan = false;
    bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by hash. Hash = " + req.hash + '.';
      return false;
    }
    if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
      return false;
    }
    uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
    bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, res.block_header);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.miner_tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(blk.miner_tx));
    for (size_t n = 0; n < blk.tx_hashes.size(); ++n)
    {
      res.tx_hashes.push_back(epee::string_tools::pod_to_hex(blk.tx_hashes[n]));
    }
    res.blob = string_tools::buff_to_hex_nodelimer(t_serializable_object_to_blob(blk));
    res.json = obj_to_json_str(blk);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_connections);

    res.connections = m_p2p.get_payload_object().get_connections();

    res.status = CORE_RPC_STATUS_OK;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info_json(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_info_json);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_INFO>(invoke_http_mode::JON_RPC, "get_info", req, res, r))
    {
      res.bootstrap_daemon_address = m_bootstrap_daemon_address;
      crypto::hash top_hash;
      m_core.get_blockchain_top(res.height_without_bootstrap, top_hash);
      ++res.height_without_bootstrap; // turn top block height into blockchain height
      res.was_bootstrap_ever_used = true;
      return r;
    }


    m_core.get_blockchain_storage().get_k_core().komodo_update(m_core);

    std::vector<uint8_t> v_hash(komodo::NOTARIZED_HASH.begin(), komodo::NOTARIZED_HASH.begin()+32);
    std::vector<uint8_t> v_txid(komodo::NOTARIZED_DESTTXID.begin(), komodo::NOTARIZED_DESTTXID.begin()+32);
    std::vector<uint8_t> v_mom(komodo::NOTARIZED_MOM.begin(), komodo::NOTARIZED_MOM.begin()+32);

    res.notarized = komodo::NOTARIZED_HEIGHT;
    res.notarizedhash = bytes256_to_hex(v_hash);
    res.notarizedtxid = bytes256_to_hex(v_txid);
    res.notarization_count = komodo::NUM_NPOINTS;
    res.notarized_MoM = bytes256_to_hex(v_mom);
    res.prevMoMheight = komodo::NOTARIZED_PREVHEIGHT;

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    res.blocks = res.height;
    ++res.height; // turn top block height into blockchain height
    res.top_block_hash = string_tools::pod_to_hex(top_hash);
    res.target_height = m_core.get_target_blockchain_height();
    res.difficulty = m_core.get_blockchain_storage().get_difficulty_for_next_block();
    res.target = DIFFICULTY_TARGET;
    res.tx_count = m_core.get_blockchain_storage().get_total_transactions() - res.height; //without coinbase
    res.tx_pool_size = m_core.get_pool_transactions_count();
    res.alt_blocks_count = m_core.get_blockchain_storage().get_alternative_blocks_count();
    uint64_t total_conn = m_p2p.get_connections_count();
    res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
    res.incoming_connections_count = total_conn - res.outgoing_connections_count;
    res.rpc_connections_count = get_connections_count();
    res.white_peerlist_size = m_p2p.get_peerlist_manager().get_white_peers_count();
    res.grey_peerlist_size = m_p2p.get_peerlist_manager().get_gray_peers_count();
    res.mainnet = m_nettype == MAINNET;
    res.testnet = m_nettype == TESTNET;
    res.stagenet = m_nettype == STAGENET;
    res.cumulative_difficulty = m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(res.height - 1);
    res.block_size_limit = m_core.get_blockchain_storage().get_current_cumulative_blocksize_limit();
    res.block_size_median = m_core.get_blockchain_storage().get_current_cumulative_blocksize_median();
    res.status = CORE_RPC_STATUS_OK;
    res.start_time = (uint64_t)m_core.get_start_time();
    res.free_space = m_restricted ? std::numeric_limits<uint64_t>::max() : m_core.get_free_space();
    res.offline = m_core.offline();
    res.bootstrap_daemon_address = m_bootstrap_daemon_address;
    res.height_without_bootstrap = res.height;
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      res.was_bootstrap_ever_used = m_was_bootstrap_ever_used;
    }
    res.version = MONERO_VERSION;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_hard_fork_info(const COMMAND_RPC_HARD_FORK_INFO::request& req, COMMAND_RPC_HARD_FORK_INFO::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_hard_fork_info);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_HARD_FORK_INFO>(invoke_http_mode::JON_RPC, "hard_fork_info", req, res, r))
      return r;

    const Blockchain &blockchain = m_core.get_blockchain_storage();
    uint8_t version = req.version > 0 ? req.version : blockchain.get_next_hard_fork_version();
    res.version = blockchain.get_current_hard_fork_version();
    res.enabled = blockchain.get_hard_fork_voting_info(version, res.window, res.votes, res.threshold, res.earliest_height, res.voting);
    res.state = blockchain.get_hard_fork_state();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_bans);

    auto now = time(nullptr);
    std::map<std::string, time_t> blocked_hosts = m_p2p.get_blocked_hosts();
    for (std::map<std::string, time_t>::const_iterator i = blocked_hosts.begin(); i != blocked_hosts.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first;
        b.ip = 0;
        uint32_t ip;
        if (epee::string_tools::get_ip_int32_from_string(ip, i->first))
          b.ip = ip;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_bans(const COMMAND_RPC_SETBANS::request& req, COMMAND_RPC_SETBANS::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_set_bans);

    for (auto i = req.bans.begin(); i != req.bans.end(); ++i)
    {
      epee::net_utils::network_address na;
      if (!i->host.empty())
      {
        if (!epee::net_utils::create_network_address(na, i->host))
        {
          error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
          error_resp.message = "Unsupported host type";
          return false;
        }
      }
      else
      {
        na = epee::net_utils::ipv4_network_address{i->ip, 0};
      }
      if (i->ban)
        m_p2p.block_host(na, i->seconds);
      else
        m_p2p.unblock_host(na);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_merkle_root(const COMMAND_RPC_GET_MERKLE_ROOT::request& req, COMMAND_RPC_GET_MERKLE_ROOT::response& res, epee::json_rpc::error& error_resp)
  {
      bool tx_filled = req.tx_hashes.size() > 0;
      bool blk_filled = req.block_hash.size() > 0;
      bool both_filled = tx_filled && blk_filled;

      if (!tx_filled && !blk_filled) {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Error: No transaction(s) or block hash given for root computation";
        return false;
      } else if (both_filled) {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Error: Too many parameters.  Please use only one of tx_hashes or block_hash.";
        return false;
      }

     std::vector<crypto::hash> tx_hashes;
     cryptonote::blobdata tmp_hash;
     crypto::hash tree_hash = crypto::null_hash;
     cryptonote::block b;

     if (tx_filled)
     {
       for (const auto& hash : req.tx_hashes)
       {
         if (!epee::string_tools::parse_hexstr_to_binbuff(hash,tmp_hash))
         {
           error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
           error_resp.message = "Error: Cannot parse tx_hash from hexstr";
           return false;
         }
         tx_hashes.push_back(*reinterpret_cast<const crypto::hash*>(tmp_hash.data()));
       }
       const std::vector<crypto::hash> const_txs = tx_hashes;
       tree_hash = get_tx_tree_hash(const_txs);
     }

     if (blk_filled)
     {
       if(!epee::string_tools::parse_hexstr_to_binbuff(req.block_hash,tmp_hash))
       {
         error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
         error_resp.message = "Error: Cannot parse blk_hash from hexstr";
         return false;
       }

       const crypto::hash* b_hash = reinterpret_cast<const crypto::hash*>(tmp_hash.data());
       if (!m_core.get_block_by_hash(*b_hash, b))
       {
         error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
         error_resp.message = "Error: Block not found for provided hash";
         return false;
       }
       tree_hash = get_tx_tree_hash(b);
     }

     std::string tree_hash_s = epee::string_tools::pod_to_hex(tree_hash);
     res.tree_hash = tree_hash_s;
     res.status = "OK";
     return true;
}

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_ntz_data(const COMMAND_RPC_GET_NTZ_DATA::request& req, COMMAND_RPC_GET_NTZ_DATA::response& res, epee::json_rpc::error& error_resp)
  {
      const char* ASSETCHAINS_SYMBOL[5] = { "BLUR" };

      uint64_t height = m_core.get_blockchain_storage().get_db().height()-1;

      if (height <= 0) {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Error: No active chain height could be found";
        return false;
      }


      m_core.get_blockchain_storage().get_k_core().komodo_update(m_core);

      std::vector<uint8_t> v_hash(komodo::NOTARIZED_HASH.begin(), komodo::NOTARIZED_HASH.begin()+32);
      std::string n_hash = bytes256_to_hex(v_hash);
      std::vector<uint8_t> v_txid(komodo::NOTARIZED_DESTTXID.begin(), komodo::NOTARIZED_DESTTXID.begin()+32);
      std::string n_txid = bytes256_to_hex(v_txid);
      std::vector<uint8_t> v_MoM(komodo::NOTARIZED_MOM.begin(), komodo::NOTARIZED_MOM.begin()+32);
      std::string n_MoM = bytes256_to_hex(v_MoM);

      cryptonote::block blk = m_core.get_blockchain_storage().get_db().get_top_block();
      crypto::hash c_hash = m_core.get_blockchain_storage().get_db().top_block_hash();
      crypto::hash c_pow = cryptonote::get_block_longhash(blk, height);
      epee::span<const uint8_t> vc_hash = as_byte_span(c_hash);
      std::string s_hash = span_to_hex(vc_hash);
      epee::span<const uint8_t> vc_pow = as_byte_span(c_pow);;
      std::string s_pow = span_to_hex(vc_pow);

      std::string ntz_txid_s = bytes256_to_hex(v_txid);

      std::string ntz_txid_bin;
      if (!epee::string_tools::parse_hexstr_to_binbuff(ntz_txid_s, ntz_txid_bin))
        MERROR("Failed to parse hexstr to binbuff!");

      crypto::hash ntz_txid = *reinterpret_cast<const crypto::hash*>(ntz_txid_bin.data());

      cryptonote::blobdata tx_blob;
      cryptonote::transaction tx;
      std::string ntz_rem, embedded_btc_data_hash;
      std::vector<uint8_t> ntz_data, new_extra, doublesha_vec;
      m_core.get_blockchain_storage().get_db().get_tx_blob(ntz_txid, tx_blob);
      if (!parse_and_validate_tx_from_blob(tx_blob, tx)) {
        MERROR("Couldn't parse tx from blob!");
      } else {
        bool rem = remove_ntz_data_from_tx_extra(tx.extra, new_extra, ntz_data, ntz_rem);
        if (rem) {
          uint8_t* ntz_data_ptr = ntz_data.data();
          bits256 bits = m_core.get_blockchain_storage().get_k_core().bits256_doublesha256(ntz_data_ptr, ntz_data.size());
          for (const auto& each : bits.bytes) {
            doublesha_vec.push_back(each);
          }
          embedded_btc_data_hash = bytes256_to_hex(doublesha_vec);
        }
      }

      uint64_t ntz_height = komodo::NOTARIZED_HEIGHT;
      uint64_t ntz_complete = komodo::NUM_NPOINTS;

      res.assetchains_symbol = komodo::ASSETCHAINS_SYMBOL;
      res.current_chain_height = height;
      res.current_chain_hash = s_hash;
      res.current_chain_pow = s_pow;
      res.notarized_hash = bytes256_to_hex(v_hash);
    /*res.notarized_pow = n_pow;*/
      res.notarized_txid = bytes256_to_hex(v_txid);
      res.embedded_btc_hash = embedded_btc_data_hash;
      res.notarized_height = ntz_height;
      res.notarizations_completed = ntz_complete;
      res.notarizations_merkle = bytes256_to_hex(v_MoM);
/*      res.prevMoMheight = komodo::komodo_prevMoMheight();
      res.notarized_MoMdepth = komodo::NOTARIZED_MOMDEPTH;
      res.notarized_MoM = n_MoM;*/

     res.status = "OK";
     return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_calc_MoM(const COMMAND_RPC_CALC_MOM::request& req, COMMAND_RPC_CALC_MOM::response& res)
  {
    uint64_t height;
    uint64_t MoMdepth;
    uint256 MoM;

    std::string s_height = req.height;
    std::string s_MoMdepth = req.MoMdepth;
    MoMdepth = std::stoull(s_MoMdepth, 0, 10);
    height = std::stoull(s_height, 0, 10);

    if ( MoMdepth >= height ) {
      res.status = "Failed! calc_MoM illegal height or MoMdepth";
      return true;
    }

    m_core.get_blockchain_storage().get_k_core().komodo_update(m_core);

    std::vector<uint8_t> v_mom(komodo::NOTARIZED_MOM.begin(), komodo::NOTARIZED_MOM.begin()+32);

    std::string str_MoM = bytes256_to_hex(v_mom);
    // use null hash as placeholder - Can change if we need this call

    char* coin = (char*)(komodo::ASSETCHAINS_SYMBOL[0] == 0 ? "KMD" : "BLUR");
    res.coin = coin;
    res.notarized_height = height;
    res.notarized_MoMdepth = MoMdepth;
    res.notarized_MoM = str_MoM;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
/*  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_height_MoM(const COMMAND_RPC_HEIGHT_MOM::request& req, COMMAND_RPC_HEIGHT_MOM::response& res, epee::json_rpc::error& error_resp)
  {
    std::string coin = (char*)(komodo::ASSETCHAINS_SYMBOL[0] == 0 ? "KMD" : komodo::ASSETCHAINS_SYMBOL);

      if (req.height == 0 || m_core.get_current_blockchain_height() == 0 )
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Error no active chain yet";
        return false;
      }
      uint64_t height = m_core.get_blockchain_storage().get_db().height()-1;

      cryptonote::block blk = m_core.get_blockchain_storage().get_db().get_block_from_height(req.height);


    uint64_t timestamp = blk.timestamp;
    int32_t notarized_height;
    uint256 MoM;
    uint256 kmdtxid;
    uint256 MoMoM;
    int32_t MoMoMoffset;
    int32_t MoMoMdepth;
    int32_t kmdstarti;
    int32_t kmdendi;

    //fprintf(stderr,"height_MoM height.%d\n",height);
    int32_t depth = komodo::komodo_MoM(&notarized_height,&MoM,&kmdtxid,height,&MoMoM,&MoMoMoffset,&MoMoMdepth,&kmdstarti,&kmdendi);
    res.coin = coin;
    res.notarized_height = notarized_height;
    res.timestamp = timestamp;
    if ( depth > 0 )
    {
        res.notarized_MoMdepth = depth;
        res.notarized_height = notarized_height;

        std::vector<uint8_t> v_MoM(MoM.begin(), MoM.begin() + 32);
        std::string str_MoM = bytes256_to_hex(v_MoM);

        std::vector<uint8_t> v_kmdtxid(kmdtxid.begin(), kmdtxid.begin() + 32);
        std::string str_kmdtxid = bytes256_to_hex(v_kmdtxid);

        res.notarized_MoM = str_MoM;
        res.notarized_desttxid = str_kmdtxid;

        if ( komodo::ASSETCHAINS_SYMBOL[0] != 0 )
        {
        std::vector<uint8_t> v_MoMoM(MoMoM.begin(), MoMoM.begin()+32);
        std::string str_MoMoM = bytes256_to_hex(v_MoMoM);

            res.MoMoM = str_MoMoM;
            res.MoMoMoffset = MoMoMoffset;
            res.MoMoMdepth = MoMoMdepth;
            res.kmdstarti = kmdstarti;
            res.kmdendi = kmdendi;
            res.status = CORE_RPC_STATUS_OK;
            return true;
        }
    } else {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Error: no MoM for height";
        return false; }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }*/
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_txpool(const COMMAND_RPC_FLUSH_TRANSACTION_POOL::request& req, COMMAND_RPC_FLUSH_TRANSACTION_POOL::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_flush_txpool);

    bool failed = false;
    std::list<crypto::hash> txids;
    if (req.txids.empty())
    {
      std::list<transaction> pool_txs;
      bool r = m_core.get_pool_transactions(pool_txs);
      if (!r)
      {
        res.status = "Failed to get both txpool & ntzpool contents";
        return false;
      }
      for (const auto &tx: pool_txs)
      {
        txids.push_back(cryptonote::get_transaction_hash(tx));
      }
    }
    else
    {
      for (const auto &str: req.txids)
      {
        cryptonote::blobdata txid_data;
        if(!epee::string_tools::parse_hexstr_to_binbuff(str, txid_data))
        {
          failed = true;
        }
        else
        {
          crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_data.data());
          txids.push_back(txid);
        }
      }
    }
    if (!m_core.get_blockchain_storage().flush_txes_from_pool(txids))
    {
        res.status = "Failed to remove one or more tx(es)";
        return false;
    }

    if (failed)
    {
      if (txids.empty())
        res.status = "Failed to parse txid";
      else
        res.status = "Failed to parse some of the txids";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_ntzpool(const COMMAND_RPC_FLUSH_NTZ_POOL::request& req, COMMAND_RPC_FLUSH_NTZ_POOL::response& res, epee::json_rpc::error& error_resp)
  {
    bool failed = false;
    std::list<crypto::hash> ntz_txids;
    if (req.txids.empty())
    {
      std::list<std::pair<transaction,blobdata>> ntzpool_txs;
      bool R = m_core.get_ntzpool_transactions(ntzpool_txs);
      if (!R)
      {
        res.status = "Failed to get ntzpool contents";
        return false;
      }
      for (const auto &tx: ntzpool_txs)
      {
        ntz_txids.push_back(cryptonote::get_transaction_hash(tx.first));
      }
    }
    else
    {
      for (const auto &str: req.txids)
      {
        cryptonote::blobdata ntz_txid_data;
        if(!epee::string_tools::parse_hexstr_to_binbuff(str, ntz_txid_data))
        {
          failed = true;
        }
        else
        {
          crypto::hash ntz_txid = *reinterpret_cast<const crypto::hash*>(ntz_txid_data.data());
          ntz_txids.push_back(ntz_txid);
        }
      }
    }
    if (!m_core.get_blockchain_storage().flush_ntz_txes_from_pool(ntz_txids))
    {
        res.status = "Failed to remove one or more tx(es)";
        return false;
    }

    if (failed)
    {
      if (ntz_txids.empty())
        res.status = "Failed to parse txid";
      else
        res.status = "Failed to parse some of the txids";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_histogram(const COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request& req, COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_output_histogram);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_OUTPUT_HISTOGRAM>(invoke_http_mode::JON_RPC, "get_output_histogram", req, res, r))
      return r;

    std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> histogram;
    try
    {
      histogram = m_core.get_blockchain_storage().get_output_histogram(req.amounts, req.unlocked, req.recent_cutoff);
    }
    catch (const std::exception &e)
    {
      res.status = "Failed to get output histogram";
      return true;
    }

    res.histogram.clear();
    res.histogram.reserve(histogram.size());
    for (const auto &i: histogram)
    {
      if (std::get<0>(i.second) >= req.min_count && (std::get<0>(i.second) <= req.max_count || req.max_count == 0))
        res.histogram.push_back(COMMAND_RPC_GET_OUTPUT_HISTOGRAM::entry(i.first, std::get<0>(i.second), std::get<1>(i.second), std::get<2>(i.second)));
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_version(const COMMAND_RPC_GET_VERSION::request& req, COMMAND_RPC_GET_VERSION::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_version);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_VERSION>(invoke_http_mode::JON_RPC, "get_version", req, res, r))
      return r;

    res.version = CORE_RPC_VERSION;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_coinbase_tx_sum(const COMMAND_RPC_GET_COINBASE_TX_SUM::request& req, COMMAND_RPC_GET_COINBASE_TX_SUM::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_coinbase_tx_sum);
    std::pair<uint64_t, uint64_t> amounts = m_core.get_coinbase_tx_sum(req.height, req.count);
    res.emission_amount = amounts.first;
    res.fee_amount = amounts.second;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_per_kb_fee_estimate(const COMMAND_RPC_GET_PER_KB_FEE_ESTIMATE::request& req, COMMAND_RPC_GET_PER_KB_FEE_ESTIMATE::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_per_kb_fee_estimate);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_PER_KB_FEE_ESTIMATE>(invoke_http_mode::JON_RPC, "get_fee_estimate", req, res, r))
      return r;

    res.fee = m_core.get_blockchain_storage().get_dynamic_per_kb_fee_estimate(req.grace_blocks);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_alternate_chains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_alternate_chains);
    try
    {
      std::list<std::pair<Blockchain::block_extended_info, uint64_t>> chains = m_core.get_blockchain_storage().get_alternative_chains();
      for (const auto &i: chains)
      {
        res.chains.push_back(COMMAND_RPC_GET_ALTERNATE_CHAINS::chain_info{epee::string_tools::pod_to_hex(get_block_hash(i.first.bl)), i.first.height, i.second, i.first.cumulative_difficulty});
      }
      res.status = CORE_RPC_STATUS_OK;
    }
    catch (...)
    {
      res.status = "Error retrieving alternate chains";
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_limit(const COMMAND_RPC_GET_LIMIT::request& req, COMMAND_RPC_GET_LIMIT::response& res)
  {
    PERF_TIMER(on_get_limit);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_LIMIT>(invoke_http_mode::JON, "/get_limit", req, res, r))
      return r;

    res.limit_down = epee::net_utils::connection_basic::get_rate_down_limit();
    res.limit_up = epee::net_utils::connection_basic::get_rate_up_limit();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_limit(const COMMAND_RPC_SET_LIMIT::request& req, COMMAND_RPC_SET_LIMIT::response& res)
  {
    PERF_TIMER(on_set_limit);
    // -1 = reset to default
    //  0 = do not modify

    if (req.limit_down > 0)
    {
      epee::net_utils::connection_basic::set_rate_down_limit(req.limit_down);
    }
    else if (req.limit_down < 0)
    {
      if (req.limit_down != -1)
      {
        res.status = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        return false;
      }
      epee::net_utils::connection_basic::set_rate_down_limit(nodetool::default_limit_down);
    }

    if (req.limit_up > 0)
    {
      epee::net_utils::connection_basic::set_rate_up_limit(req.limit_up);
    }
    else if (req.limit_up < 0)
    {
      if (req.limit_up != -1)
      {
        res.status = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        return false;
      }
      epee::net_utils::connection_basic::set_rate_up_limit(nodetool::default_limit_up);
    }

    res.limit_down = epee::net_utils::connection_basic::get_rate_down_limit();
    res.limit_up = epee::net_utils::connection_basic::get_rate_up_limit();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_out_peers(const COMMAND_RPC_OUT_PEERS::request& req, COMMAND_RPC_OUT_PEERS::response& res)
  {
    PERF_TIMER(on_out_peers);
    size_t n_connections = m_p2p.get_outgoing_connections_count();
    size_t n_delete = (n_connections > req.out_peers) ? n_connections - req.out_peers : 0;
    m_p2p.m_config.m_net_config.max_out_connection_count = req.out_peers;
    if (n_delete)
      m_p2p.delete_out_connections(n_delete);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_in_peers(const COMMAND_RPC_IN_PEERS::request& req, COMMAND_RPC_IN_PEERS::response& res)
  {
    PERF_TIMER(on_in_peers);
    size_t n_connections = m_p2p.get_incoming_connections_count();
    size_t n_delete = (n_connections > req.in_peers) ? n_connections - req.in_peers : 0;
    m_p2p.m_config.m_net_config.max_in_connection_count = req.in_peers;
    if (n_delete)
      m_p2p.delete_in_connections(n_delete);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_relay_tx(const COMMAND_RPC_RELAY_TX::request& req, COMMAND_RPC_RELAY_TX::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_relay_tx);

    bool failed = false;
    res.status = "";
    for (const auto &str: req.txids)
    {
      cryptonote::blobdata txid_data;
      if(!epee::string_tools::parse_hexstr_to_binbuff(str, txid_data))
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("invalid transaction id: ") + str;
        failed = true;
        continue;
      }
      crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_data.data());

      cryptonote::blobdata txblob;
      bool r = m_core.get_pool_transaction(txid, txblob);
      if (r)
      {
        cryptonote_connection_context fake_context;
        NOTIFY_NEW_TRANSACTIONS::request r;
        r.txs.push_back(txblob);
        m_core.get_protocol()->relay_transactions(r, fake_context);
        //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
      }
      else
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("transaction not found in pool: ") + str;
        failed = true;
        continue;
      }
    }

    if (failed)
    {
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_relay_ntzpool_tx(const COMMAND_RPC_RELAY_NTZPOOL_TX::request& req, COMMAND_RPC_RELAY_NTZPOOL_TX::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_relay_ntzpool_tx);

    bool failed = false;
    res.status = "";
    for (const auto &str: req.txids)
    {
      cryptonote::blobdata txid_data;
      if(!epee::string_tools::parse_hexstr_to_binbuff(str, txid_data))
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("invalid transaction id: ") + str;
        failed = true;
        continue;
      }
      crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_data.data());

      cryptonote::blobdata txblob;
      cryptonote::blobdata ptxblob;
      ntzpool_tx_meta_t meta = AUTO_VAL_INIT(meta);
      bool r = m_core.get_ntzpool_transaction(txid, txblob, ptxblob);
      if (r)
      {
        if (!m_core.get_blockchain_storage().get_ntzpool_tx_meta(txid, meta)) {
          if (!res.status.empty()) res.status += ", ";
          res.status += "failed to get meta for tx with hash: " + str;
          failed = true;
          continue;
        }

        cryptonote_connection_context fake_context;
        NOTIFY_REQUEST_NTZ_SIG::request r;
        r.ptx_string = ptxblob;
        r.ptx_hash = meta.ptx_hash;
        r.tx_blob = txblob;
        r.sig_count = meta.sig_count;
        for (size_t i = 0; i < DPOW_SIG_COUNT; i++) {
          int each_ind = meta.signers_index[i];
          r.signers_index.push_back(each_ind);
        }
        m_core.get_protocol()->relay_request_ntz_sig(r, fake_context);
        //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
      }
      else
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("transaction not found in pool: ") + str;
        failed = true;
        continue;
      }
    }

    if (failed)
    {
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_sync_info(const COMMAND_RPC_SYNC_INFO::request& req, COMMAND_RPC_SYNC_INFO::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_sync_info);

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.target_height = m_core.get_target_blockchain_height();

    for (const auto &c: m_p2p.get_payload_object().get_connections())
      res.peers.push_back({c});
    const cryptonote::block_queue &block_queue = m_p2p.get_payload_object().get_block_queue();
    block_queue.foreach([&](const cryptonote::block_queue::span &span) {
      const std::string span_connection_id = epee::string_tools::pod_to_hex(span.connection_id);
      uint32_t speed = (uint32_t)(100.0f * block_queue.get_speed(span.connection_id) + 0.5f);
      std::string address = "";
      for (const auto &c: m_p2p.get_payload_object().get_connections())
        if (c.connection_id == span_connection_id)
          address = c.address;
      res.spans.push_back({span.start_block_height, span.nblocks, span_connection_id, (uint32_t)(span.rate + 0.5f), speed, span.size, address});
      return true;
    });

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_txpool_backlog(const COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::response& res, epee::json_rpc::error& error_resp)
  {
    PERF_TIMER(on_get_txpool_backlog);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG>(invoke_http_mode::JON_RPC, "get_txpool_backlog", req, res, r))
      return r;

    if (!m_core.get_txpool_backlog(res.backlog))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to get txpool backlog";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_distribution(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, epee::json_rpc::error& error_resp)
  {
    try
    {
      for (uint64_t amount: req.amounts)
      {
        std::vector<uint64_t> distribution;
        uint64_t start_height, base;
        if (!m_core.get_output_distribution(amount, req.from_height, start_height, distribution, base))
        {
          error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
          error_resp.message = "Failed to get rct distribution";
          return false;
        }
        if (req.cumulative)
        {
          distribution[0] += base;
          for (size_t n = 1; n < distribution.size(); ++n)
            distribution[n] += distribution[n-1];
        }
        res.distributions.push_back({amount, start_height, std::move(distribution), base});
      }
    }
    catch (const std::exception &e)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to get output distribution";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------


  const command_line::arg_descriptor<std::string, false, true, 2> core_rpc_server::arg_rpc_bind_port = {
      "rpc-bind-port"
    , "Port for RPC server"
    , std::to_string(config::RPC_DEFAULT_PORT)
    , {{ &cryptonote::arg_testnet_on, &cryptonote::arg_stagenet_on }}
    , [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
        if (testnet_stagenet[0] && defaulted)
          return std::to_string(config::testnet::RPC_DEFAULT_PORT);
        else if (testnet_stagenet[1] && defaulted)
          return std::to_string(config::stagenet::RPC_DEFAULT_PORT);
        return val;
      }
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_rpc_restricted_bind_port = {
      "rpc-restricted-bind-port"
    , "Port for restricted RPC server"
    , ""
    };

  const command_line::arg_descriptor<bool> core_rpc_server::arg_restricted_rpc = {
      "restricted-rpc"
    , "Restrict RPC to view only commands and do not return privacy sensitive data in RPC calls"
    , false
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_address = {
      "bootstrap-daemon-address"
    , "URL of a 'bootstrap' remote daemon that the connected wallets can use while this daemon is still not fully synced"
    , ""
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_login = {
      "bootstrap-daemon-login"
    , "Specify username:password for the bootstrap daemon login"
    , ""
    };
}  // namespace cryptonote
