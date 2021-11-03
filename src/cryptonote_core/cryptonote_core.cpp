// Copyright (c) 2018-2022, Blur Network
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

#include <boost/algorithm/string.hpp>

#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include <unordered_set>
#include <csignal>
#include "common/command_line.h"
#include "common/util.h"
#include "common/threadpool.h"
#include "common/command_line.h"
#include "common/hex_str.h"
#include "warnings.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "cryptonote_tx_utils.h"
#include "misc_language.h"
#include "file_io_utils.h"
#include "checkpoints/checkpoints.h"
#include "ringct/rctTypes.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_core.h"
#include "cryptonote_basic/komodo_notaries.h"
#include "ringct/rctSigs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

DISABLE_VS_WARNINGS(4355)

#define MERROR_VER(x) MCERROR("verify", x)

#define BAD_SEMANTICS_TXES_MAX_SIZE 100

namespace cryptonote
{
  const command_line::arg_descriptor<bool, false> arg_testnet_on  = {
    "testnet"
  , "Run on testnet. The wallet must be launched with --testnet flag."
  , false
  };
  const command_line::arg_descriptor<bool, false> arg_stagenet_on  = {
    "stagenet"
  , "Run on stagenet. The wallet must be launched with --stagenet flag."
  , false
  };
  const command_line::arg_descriptor<std::string, false, true, 2> arg_data_dir = {
    "data-dir"
  , "Specify data directory"
  , tools::get_default_data_dir()
  , {{ &arg_testnet_on, &arg_stagenet_on }}
  , [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
      if (testnet_stagenet[0])
        return (boost::filesystem::path(val) / "testnet").string();
      else if (testnet_stagenet[1])
        return (boost::filesystem::path(val) / "stagenet").string();
      return val;
    }
  };
  const command_line::arg_descriptor<bool> arg_offline = {
    "offline"
  , "Do not listen for peers, nor connect to any"
  };
  static const command_line::arg_descriptor<bool> arg_test_drop_download = {
    "test-drop-download"
  , "For net tests: in download, discard ALL blocks instead checking/saving them (very fast)"
  };
  static const command_line::arg_descriptor<uint64_t> arg_test_drop_download_height = {
    "test-drop-download-height"
  , "Like test-drop-download but discards only after around certain height"
  , 0
  };
  static const command_line::arg_descriptor<int> arg_test_dbg_lock_sleep = {
    "test-dbg-lock-sleep"
  , "Sleep time in ms, defaults to 0 (off), used to debug before/after locking mutex. Values 100 to 1000 are good for tests."
  , 0
  };
  static const command_line::arg_descriptor<uint64_t> arg_fast_block_sync = {
    "fast-block-sync"
  , "Sync up most of the way by using embedded, known block hashes."
  , 1
  };
  static const command_line::arg_descriptor<uint64_t> arg_prep_blocks_threads = {
    "prep-blocks-threads"
  , "Max number of threads to use when preparing block hashes in groups."
  , 4
  };
  static const command_line::arg_descriptor<uint64_t> arg_show_time_stats  = {
    "show-time-stats"
  , "Show time-stats when processing blocks/txs and disk synchronization."
  , 0
  };
  static const command_line::arg_descriptor<size_t> arg_block_sync_size  = {
    "block-sync-size"
  , "How many blocks to sync at once during chain synchronization (0 = adaptive)."
  , 0
  };
  static const command_line::arg_descriptor<bool> arg_fluffy_blocks  = {
    "fluffy-blocks"
  , "Relay blocks as fluffy blocks (obsolete, now default)"
  , true
  };
  static const command_line::arg_descriptor<bool> arg_no_fluffy_blocks  = {
    "no-fluffy-blocks"
  , "Relay blocks as normal blocks"
  , false
  };
  static const command_line::arg_descriptor<size_t> arg_max_txpool_size  = {
    "max-txpool-size"
  , "Set maximum txpool size in bytes."
  , DEFAULT_TXPOOL_MAX_SIZE
  };

  //-----------------------------------------------------------------------------------------------
  core::core(i_cryptonote_protocol* pprotocol):
              m_mempool(m_blockchain_storage),
              m_blockchain_storage(m_mempool),
              m_miner(this),
              m_miner_address(boost::value_initialized<account_public_address>()),
              m_starter_message_showed(false),
              m_target_blockchain_height(0),
              m_checkpoints_path(""),
              m_last_json_checkpoints_update(0),
              m_threadpool(tools::threadpool::getInstance()),
              m_nettype(UNDEFINED)
  {
    m_checkpoints_updating.clear();
    set_cryptonote_protocol(pprotocol);
  }
  void core::set_cryptonote_protocol(i_cryptonote_protocol* pprotocol)
  {
    if(pprotocol)
      m_pprotocol = pprotocol;
    else
      m_pprotocol = &m_protocol_stub;
  }
  //-----------------------------------------------------------------------------------
  void core::set_checkpoints(checkpoints&& chk_pts)
  {
    m_blockchain_storage.set_checkpoints(std::move(chk_pts));
  }
  //-----------------------------------------------------------------------------------
  void core::set_checkpoints_file_path(const std::string& path)
  {
    m_checkpoints_path = path;
  }
  //-----------------------------------------------------------------------------------
  bool core::update_checkpoints()
  {
    if (m_nettype != cryptonote::MAINNET) return true;

    if (m_checkpoints_updating.test_and_set()) return true;

    bool res = true;
    if (time(NULL) - m_last_json_checkpoints_update >= 600)
    {
      res = m_blockchain_storage.update_checkpoints(m_checkpoints_path);
      m_last_json_checkpoints_update = time(NULL);
    }

    m_checkpoints_updating.clear();

    // if anything fishy happened getting new checkpoints, bring down the house
    if (!res)
    {
      graceful_exit();
    }
    return res;
  }
  //-----------------------------------------------------------------------------------
  void core::stop()
  {
    m_blockchain_storage.cancel();
  }
  //-----------------------------------------------------------------------------------
  void core::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_data_dir);

    command_line::add_arg(desc, arg_test_drop_download);
    command_line::add_arg(desc, arg_test_drop_download_height);

    command_line::add_arg(desc, arg_testnet_on);
    command_line::add_arg(desc, arg_stagenet_on);
    command_line::add_arg(desc, arg_prep_blocks_threads);
    command_line::add_arg(desc, arg_fast_block_sync);
    command_line::add_arg(desc, arg_show_time_stats);
    command_line::add_arg(desc, arg_block_sync_size);
    command_line::add_arg(desc, arg_fluffy_blocks);
    command_line::add_arg(desc, arg_no_fluffy_blocks);
    command_line::add_arg(desc, arg_test_dbg_lock_sleep);
    command_line::add_arg(desc, arg_offline);
    command_line::add_arg(desc, arg_max_txpool_size);

    miner::init_options(desc);
    BlockchainDB::init_options(desc);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_command_line(const boost::program_options::variables_map& vm)
  {
    if (m_nettype != cryptonote::FAKECHAIN)
    {
      const bool testnet = command_line::get_arg(vm, arg_testnet_on);
      const bool stagenet = command_line::get_arg(vm, arg_stagenet_on);
      m_nettype = testnet ? cryptonote::TESTNET : stagenet ? cryptonote::STAGENET : cryptonote::MAINNET;
    }

    m_config_folder = command_line::get_arg(vm, arg_data_dir);

    auto data_dir = boost::filesystem::path(m_config_folder);

    if (m_nettype == cryptonote::MAINNET)
    {
      cryptonote::checkpoints checkpoints;
      if (!checkpoints.init_default_checkpoints(m_nettype))
      {
        throw std::runtime_error("Failed to initialize checkpoints");
      }
      set_checkpoints(std::move(checkpoints));

      boost::filesystem::path json(JSON_HASH_FILE_NAME);
      boost::filesystem::path checkpoint_json_hashfile_fullpath = data_dir / json;

      set_checkpoints_file_path(checkpoint_json_hashfile_fullpath.string());
    }


    test_drop_download_height(command_line::get_arg(vm, arg_test_drop_download_height));
    m_fluffy_blocks_enabled = !get_arg(vm, arg_no_fluffy_blocks);
    m_offline = get_arg(vm, arg_offline);
    if (!command_line::is_arg_defaulted(vm, arg_fluffy_blocks))
      MWARNING(arg_fluffy_blocks.name << " is obsolete, it is now default");

    if (command_line::get_arg(vm, arg_test_drop_download) == true)
      test_drop_download();

    epee::debug::g_test_dbg_lock_sleep() = command_line::get_arg(vm, arg_test_dbg_lock_sleep);

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_current_blockchain_height() const
  {
    return m_blockchain_storage.get_current_blockchain_height();
  }
  //-----------------------------------------------------------------------------------------------
  void core::get_blockchain_top(uint64_t& height, crypto::hash& top_id) const
  {
    top_id = m_blockchain_storage.get_tail_id(height);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::list<std::pair<cryptonote::blobdata,block>>& blocks, std::list<cryptonote::blobdata>& txs) const
  {
    return m_blockchain_storage.get_blocks(start_offset, count, blocks, txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::list<std::pair<cryptonote::blobdata,block>>& blocks) const
  {
    return m_blockchain_storage.get_blocks(start_offset, count, blocks);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::list<block>& blocks) const
  {
    std::list<std::pair<cryptonote::blobdata, cryptonote::block>> bs;
    if (!m_blockchain_storage.get_blocks(start_offset, count, bs))
      return false;
    for (const auto &b: bs)
      blocks.push_back(b.second);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_transactions(const std::vector<crypto::hash>& txs_ids, std::list<cryptonote::blobdata>& txs, std::list<crypto::hash>& missed_txs) const
  {
    return m_blockchain_storage.get_transactions_blobs(txs_ids, txs, missed_txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_txpool_backlog(std::vector<tx_backlog_entry>& backlog) const
  {
    m_mempool.get_transaction_backlog(backlog);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_transactions(const std::vector<crypto::hash>& txs_ids, std::list<transaction>& txs, std::list<crypto::hash>& missed_txs) const
  {
    return m_blockchain_storage.get_transactions(txs_ids, txs, missed_txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_alternative_blocks(std::list<block>& blocks) const
  {
    return m_blockchain_storage.get_alternative_blocks(blocks);
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_notarization_wait() const
  {
    return m_blockchain_storage.get_notarization_wait();
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_alternative_blocks_count() const
  {
    return m_blockchain_storage.get_alternative_blocks_count();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::init(const boost::program_options::variables_map& vm, const char *config_subdir, const cryptonote::test_options *test_options)
  {
    start_time = std::time(nullptr);

    if (test_options != NULL)
    {
      m_nettype = cryptonote::FAKECHAIN;
    }
    bool r = handle_command_line(vm);
    std::string m_config_folder_mempool = m_config_folder;

    if (config_subdir)
      m_config_folder_mempool = m_config_folder_mempool + "/" + config_subdir;

    std::string db_type = command_line::get_arg(vm, cryptonote::arg_db_type);
    std::string db_sync_mode = command_line::get_arg(vm, cryptonote::arg_db_sync_mode);
    bool db_salvage = command_line::get_arg(vm, cryptonote::arg_db_salvage) != 0;
    bool fast_sync = command_line::get_arg(vm, arg_fast_block_sync) != 0;
    uint64_t blocks_threads = command_line::get_arg(vm, arg_prep_blocks_threads);
    size_t max_txpool_size = command_line::get_arg(vm, arg_max_txpool_size);

    boost::filesystem::path folder(m_config_folder);
    if (m_nettype == cryptonote::FAKECHAIN)
      folder = "fake";

    // make sure the data directory exists, and try to lock it
    CHECK_AND_ASSERT_MES (boost::filesystem::exists(folder) || boost::filesystem::create_directories(folder), false,
      std::string("Failed to create directory ").append(folder.string()).c_str());

    // check for blockchain.bin
    try
    {
      const boost::filesystem::path old_files = folder;
      if (boost::filesystem::exists(old_files / "blockchain.bin"))
      {
        MWARNING("Found old-style blockchain.bin in " << old_files.string());
        MWARNING("BLUR now uses a new format. You can either remove blockchain.bin to start syncing");
        MWARNING("the blockchain anew, or use blur-blockchain-export and blur-blockchain-import to");
        MWARNING("convert your existing blockchain.bin to the new format. See README.md for instructions.");
        return false;
      }
    }
    // folder might not be a directory, etc, etc
    catch (...) {  }

    std::unique_ptr<BlockchainDB> db(new_db(db_type));
    if (db == NULL)
    {
      LOG_ERROR("Attempted to use non-existent database type");
      return false;
    }

    folder /= db->get_db_name();
    MGINFO("Loading blockchain from folder " << folder.string() << " ...");

    const std::string filename = folder.string();
    // default to fast:async:1
    blockchain_db_sync_mode sync_mode = db_defaultsync;
    uint64_t blocks_per_sync = 1;

    try
    {
      uint64_t db_flags = 0;

      std::vector<std::string> options;
      boost::trim(db_sync_mode);
      boost::split(options, db_sync_mode, boost::is_any_of(" :"));

      for(const auto &option : options)
        MDEBUG("option: " << option);

      // default to fast:async:1
      uint64_t DEFAULT_FLAGS = DBF_FAST;

      if(options.size() == 0)
      {
        // default to fast:async:1
        db_flags = DEFAULT_FLAGS;
      }

      bool safemode = false;
      if(options.size() >= 1)
      {
        if(options[0] == "safe")
        {
          safemode = true;
          db_flags = DBF_SAFE;
          sync_mode = db_nosync;
        }
        else if(options[0] == "fast")
        {
          db_flags = DBF_FAST;
          sync_mode = db_async;
        }
        else if(options[0] == "fastest")
        {
          db_flags = DBF_FASTEST;
          blocks_per_sync = 1000; // default to fastest:async:1000
          sync_mode = db_async;
        }
        else
          db_flags = DEFAULT_FLAGS;
      }

      if(options.size() >= 2 && !safemode)
      {
        if(options[1] == "sync")
          sync_mode = db_sync;
        else if(options[1] == "async")
          sync_mode = db_async;
      }

      if(options.size() >= 3 && !safemode)
      {
        char *endptr;
        uint64_t bps = strtoull(options[2].c_str(), &endptr, 0);
        if (*endptr == '\0')
          blocks_per_sync = bps;
      }

      if (db_salvage)
        db_flags |= DBF_SALVAGE;

      db->open(filename, db_flags);
      if(!db->m_open)
        return false;
    }
    catch (const DB_ERROR& e)
    {
      LOG_ERROR("Error opening database: " << e.what());
      return false;
    }

    m_blockchain_storage.set_user_options(blocks_threads,
        blocks_per_sync, sync_mode, fast_sync);

    r = m_blockchain_storage.init(db.release(), m_nettype, m_offline, test_options);

    r = m_mempool.init(max_txpool_size);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize memory pool");

    // now that we have a valid m_blockchain_storage, we can clean out any
    // transactions in the pool that do not conform to the current fork
    m_mempool.validate(m_blockchain_storage.get_current_hard_fork_version());

    bool show_time_stats = command_line::get_arg(vm, arg_show_time_stats) != 0;
    m_blockchain_storage.set_show_time_stats(show_time_stats);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize blockchain storage");

    m_blockchain_storage.komodo_update();

    block_sync_size = command_line::get_arg(vm, arg_block_sync_size);

    MGINFO("Loading checkpoints");

    // load json checkpoints, and verify them
    // with respect to what blocks we already have
    CHECK_AND_ASSERT_MES(update_checkpoints(), false, "One or more checkpoints loaded from json conflicted with existing checkpoints.");

    r = m_miner.init(vm, m_nettype);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize miner instance");

    return load_state_data();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::set_genesis_block(const block& b)
  {
    return m_blockchain_storage.reset_and_set_genesis_block(b);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::load_state_data()
  {
    // may be some code later
    return true;
  }
  //-----------------------------------------------------------------------------------------------
    bool core::deinit()
  {
    m_miner.stop();
    m_mempool.deinit();
    m_blockchain_storage.deinit();
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::test_drop_download()
  {
    m_test_drop_download = false;
  }
  //-----------------------------------------------------------------------------------------------
  void core::test_drop_download_height(uint64_t height)
  {
    m_test_drop_download_height = height;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_test_drop_download() const
  {
    return m_test_drop_download;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_test_drop_download_height() const
  {
    if (m_test_drop_download_height == 0)
      return true;

    if (get_blockchain_storage().get_current_blockchain_height() <= m_test_drop_download_height)
      return true;

    return false;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_tx_pre(const blobdata& tx_blob, tx_verification_context& tvc, cryptonote::transaction &tx, crypto::hash &tx_hash, crypto::hash &tx_prefixt_hash, bool keeped_by_block, bool relayed, bool do_not_relay)
  {
    tvc = boost::value_initialized<tx_verification_context>();

    if(tx_blob.size() > get_max_tx_size())
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, too big size " << tx_blob.size() << ", rejected");
      tvc.m_verifivation_failed = true;
      tvc.m_too_big = true;
      return false;
    }

    tx_hash = crypto::null_hash;
    tx_prefixt_hash = crypto::null_hash;

    if(!parse_tx_from_blob(tx, tx_hash, tx_prefixt_hash, tx_blob))
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, Failed to parse, rejected");
      tvc.m_verifivation_failed = true;
      return false;
    }

    // TODO-TK: need to consider tx versioning standard.
    const size_t max_tx_version = 2;
    uint8_t version = m_blockchain_storage.get_current_hard_fork_version();
    if ((tx.version == 0) || (tx.version > max_tx_version))
    {
      // v2 is the latest one we know
      tvc.m_verifivation_failed = true;
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_tx_post(const blobdata& tx_blob, tx_verification_context& tvc, cryptonote::transaction &tx, crypto::hash &tx_hash, crypto::hash &tx_prefixt_hash, bool keeped_by_block, bool relayed, bool do_not_relay)
  {
    if(!check_tx_syntax(tx))
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, Failed to check tx " << tx_hash << " syntax, rejected");
      tvc.m_verifivation_failed = true;
      return false;
    }

    // resolve outPk references in rct txes
    // outPk aren't the only thing that need resolving for a fully resolved tx,
    // but outPk (1) are needed now to check range proof semantics, and
    // (2) do not need access to the blockchain to find data
    if (tx.version >= 1)
    {
      rct::rctSig &rv = tx.rct_signatures;
      if (rv.outPk.size() != tx.vout.size())
      {
        LOG_PRINT_L1("WRONG TRANSACTION BLOB, Bad outPk size in tx " << tx_hash << ", rejected");
        tvc.m_verifivation_failed = true;
        return false;
      }
      for (size_t n = 0; n < tx.rct_signatures.outPk.size(); ++n)
        rv.outPk[n].dest = rct::pk2rct(boost::get<txout_to_key>(tx.vout[n].target).key);

      const bool bulletproof = rv.type == rct::RCTTypeFullBulletproof || rv.type == rct::RCTTypeSimpleBulletproof;
      if (bulletproof)
      {
        if (rv.p.bulletproofs.size() != tx.vout.size())
        {
          LOG_PRINT_L1("WRONG TRANSACTION BLOB, Bad bulletproofs size in tx " << tx_hash << ", rejected");
          tvc.m_verifivation_failed = true;
          return false;
        }
        for (size_t n = 0; n < rv.outPk.size(); ++n)
        {
          rv.p.bulletproofs[n].V.resize(1);
          rv.p.bulletproofs[n].V[0] = rv.outPk[n].mask;
        }
      }
    }

    if (keeped_by_block && get_blockchain_storage().is_within_compiled_block_hash_area())
    {
      MTRACE("Asked to skip semantics check for tx kept by block in embedded hash area");
    }
    if (!check_tx_semantic(tx, keeped_by_block))
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, Failed to check tx " << tx_hash << " semantic, rejected");
      tvc.m_verifivation_failed = true;
      bad_semantics_txes_lock.lock();
      bad_semantics_txes[0].insert(tx_hash);
      if (bad_semantics_txes[0].size() >= BAD_SEMANTICS_TXES_MAX_SIZE)
      {
        std::swap(bad_semantics_txes[0], bad_semantics_txes[1]);
        bad_semantics_txes[0].clear();
      }
      bad_semantics_txes_lock.unlock();
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_ntz_sig_pre(const blobdata& tx_blob, ntz_req_verification_context& tvc, cryptonote::transaction &tx, crypto::hash&tx_hash, crypto::hash &tx_prefixt_hash, bool keeped_by_block, bool relayed, bool do_not_relay, int const& sig_count, cryptonote_connection_context const& context)
  {
    // TODO: this is a placeholder for verification

    tvc = boost::value_initialized<ntz_req_verification_context>();
    if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash, tx_prefixt_hash))
    {
      MERROR("Failed to parse tx from blob in handle_incoming_ntz_sig_pre!");
      tvc.m_verifivation_failed = true;
      return false;
    }
    MINFO("New notarization signature request for tx with hash: " << epee::string_tools::pod_to_hex(tx_hash) << ", connection context: " << context);
    if(tx_blob.size() > get_max_tx_size())
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, too big size " << tx_blob.size() << ", rejected");
      tvc.m_verifivation_failed = true;
      tvc.m_too_big = true;
      return false;
    }

    const size_t max_tx_version = 2;
    if (tx.version != (DPOW_NOTA_TX_VERSION))
    {
      MERROR("Received ntz_sig request with incorrect tx version = " << std::to_string(tx.version));
      tvc.m_verifivation_failed = true;
      return false;
    }

    if (!check_signer_index_with_viewkeys(tx))
    {
      MERROR("Viewkey check failed against tx destination!");
      tvc.m_verifivation_failed = true;
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_ntz_sig_post(const blobdata& tx_blob, ntz_req_verification_context& tvc, cryptonote::transaction &tx, crypto::hash &tx_hash, crypto::hash &tx_prefixt_hash, bool keeped_by_block, bool relayed, bool do_not_relay, const int& sig_count, cryptonote::blobdata const& ptx_string)
  {

    // TODO: this is a placeholder for verification

    // resolve outPk references in rct txes
    // outPk aren't the only thing that need resolving for a fully resolved tx,
    // but outPk (1) are needed now to check range proof semantics, and
    // (2) do not need access to the blockchain to find data
    if (tx.version >= 1)
    {
      rct::rctSig &rv = tx.rct_signatures;
      if (rv.outPk.size() != tx.vout.size())
      {
        LOG_PRINT_L1("WRONG TRANSACTION BLOB, Bad outPk size in tx " << tx_hash << ", rejected");
        tvc.m_verifivation_failed = true;
        return false;
      }
      for (size_t n = 0; n < tx.rct_signatures.outPk.size(); ++n)
        rv.outPk[n].dest = rct::pk2rct(boost::get<txout_to_key>(tx.vout[n].target).key);

      const bool bulletproof = rv.type == rct::RCTTypeFullBulletproof || rv.type == rct::RCTTypeSimpleBulletproof;
      if (bulletproof)
      {
        if (rv.p.bulletproofs.size() != tx.vout.size())
        {
          LOG_PRINT_L1("WRONG TRANSACTION BLOB, Bad bulletproofs size in tx " << tx_hash << ", rejected");
          tvc.m_verifivation_failed = true;
          return false;
        }
        for (size_t n = 0; n < rv.outPk.size(); ++n)
        {
          rv.p.bulletproofs[n].V.resize(1);
          rv.p.bulletproofs[n].V[0] = rv.outPk[n].mask;
        }
      }
    }

    m_mempool.cleanup_ntzpool();
/*    if (keeped_by_block && get_blockchain_storage().is_within_compiled_block_hash_area())
    {
      MTRACE("Asked to skip semantics check for tx kept by block in embedded hash area");
    }
    if (!check_tx_semantic(tx, keeped_by_block))
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, Failed to check tx " << tx_hash << " semantic, rejected");
      tvc.m_verifivation_failed = true;
      return false;
    }
*/
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_txs(const std::list<blobdata>& tx_blobs, std::vector<tx_verification_context>& tvc, bool keeped_by_block, bool relayed, bool do_not_relay)
  {
    TRY_ENTRY();
    CRITICAL_REGION_LOCAL(m_incoming_tx_lock);

    struct result { bool res; cryptonote::transaction tx; crypto::hash hash; crypto::hash prefix_hash; bool in_txpool; bool in_blockchain; };
    std::vector<result> results(tx_blobs.size());

    tvc.resize(tx_blobs.size());
    tools::threadpool::waiter waiter;
    std::list<blobdata>::const_iterator it = tx_blobs.begin();
    for (size_t i = 0; i < tx_blobs.size(); i++, ++it) {
      m_threadpool.submit(&waiter, [&, i, it] {
        try
        {
          results[i].res = handle_incoming_tx_pre(*it, tvc[i], results[i].tx, results[i].hash, results[i].prefix_hash, keeped_by_block, relayed, do_not_relay);
        }
        catch (const std::exception &e)
        {
          MERROR_VER("Exception in handle_incoming_tx_pre: " << e.what());
          results[i].res = false;
        }
      });
    }
    waiter.wait();
    it = tx_blobs.begin();
    std::vector<bool> already_have(tx_blobs.size(), false);
    for (size_t i = 0; i < tx_blobs.size(); i++, ++it) {
      if (!results[i].res)
        continue;
      if(m_mempool.have_tx(results[i].hash))
      {
        LOG_PRINT_L2("tx " << results[i].hash << "already have transaction in tx_pool");
        already_have[i] = true;
      }
      else if(m_blockchain_storage.have_tx(results[i].hash))
      {
        LOG_PRINT_L2("tx " << results[i].hash << " already have transaction in blockchain");
        already_have[i] = true;
      }
      else
      {
        m_threadpool.submit(&waiter, [&, i, it] {
          try
          {
            results[i].res = handle_incoming_tx_post(*it, tvc[i], results[i].tx, results[i].hash, results[i].prefix_hash, keeped_by_block, relayed, do_not_relay);
          }
          catch (const std::exception &e)
          {
            MERROR_VER("Exception in handle_incoming_tx_post: " << e.what());
            results[i].res = false;
          }
        });
      }
    }
    waiter.wait();

    bool ok = true;
    it = tx_blobs.begin();
    for (size_t i = 0; i < tx_blobs.size(); i++, ++it) {

      if (!results[i].res) {
        ok = false;
        continue; }

      if (keeped_by_block) {
        get_blockchain_storage().on_new_tx_from_block(results[i].tx); }

      if (already_have[i]) {
        continue; }

      if ((results[i].tx.version == (DPOW_NOTA_TX_VERSION)) && (get_blockchain_storage().get_db().height() < get_notarization_wait())) {
        crypto::hash tx_hash = get_transaction_hash(results[i].tx);
        LOG_PRINT_L1("skipping nota tx seen within notarization wait: [" << epee::string_tools::pod_to_hex(tx_hash) << "]");
        continue;
      }

      ok &= add_new_tx(results[i].tx, results[i].hash, results[i].prefix_hash, it->size(), tvc[i], keeped_by_block, relayed, do_not_relay);
      if(tvc[i].m_verifivation_failed)
      {MERROR_VER("Transaction verification failed: " << results[i].hash);}
      else if(tvc[i].m_verifivation_impossible)
      {MERROR_VER("Transaction verification impossible: " << results[i].hash);}

      if(tvc[i].m_added_to_pool)
        MDEBUG("tx added: " << results[i].hash);
    }
    return ok;

    CATCH_ENTRY_L0("core::handle_incoming_txs()", false);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_tx(const blobdata& tx_blob, tx_verification_context& tvc, bool keeped_by_block, bool relayed, bool do_not_relay)
  {
    std::list<cryptonote::blobdata> tx_blobs;
    tx_blobs.push_back(tx_blob);
    std::vector<tx_verification_context> tvcv(1);
    bool r = handle_incoming_txs(tx_blobs, tvcv, keeped_by_block, relayed, do_not_relay);
    tvc = tvcv[0];
    return r;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_ntz_sig(const blobdata& tx_blob, crypto::hash const& tx_hash, ntz_req_verification_context& tvc, bool keeped_by_block, bool relayed, bool do_not_relay, int const& sig_count, std::string const& signers_index, cryptonote::blobdata const& ptx_blob, crypto::hash const& ptx_hash, crypto::hash const& prior_tx_hash, crypto::hash const& prior_ptx_hash, cryptonote_connection_context const& context)
  {
    CRITICAL_REGION_LOCAL(m_incoming_tx_lock);

    bool res = false;
    cryptonote::transaction tx; crypto::hash hash = crypto::null_hash; crypto::hash prefix_hash = crypto::null_hash; bool in_txpool = false; bool in_blockchain = false;
    if (!handle_incoming_ntz_sig_pre(tx_blob, tvc, tx, hash, prefix_hash, keeped_by_block, relayed, do_not_relay, sig_count, context))
    {
      return false;
    }
    bool already_have = false;
    if(m_mempool.have_tx(hash))
    {
      LOG_PRINT_L2("tx " << hash << "already have transaction in tx_pool");
      already_have = true;
    }
    else if(m_blockchain_storage.have_tx(hash))
    {
      LOG_PRINT_L2("tx " << hash << " already have transaction in blockchain");
      already_have = true;
    }

    if ((sig_count <= DPOW_SIG_COUNT) && (!already_have)) {
        res = handle_incoming_ntz_sig_post(tx_blob, tvc, tx, hash, prefix_hash, keeped_by_block, relayed, do_not_relay, sig_count, ptx_blob);
      if (!res) {
        MERROR("Error in handle_incoming_ntz_sig_post! handle_incoming_post failed!");
        tvc.m_verifivation_failed = true;
      }
    }

    bool ok = false;

    if (keeped_by_block) {
      get_blockchain_storage().on_new_tx_from_block(tx);
    }
    if (res) {
      ok = add_new_ntz_req(tx, hash, prefix_hash, tx_blob.size(), tvc, keeped_by_block, relayed, do_not_relay, sig_count, signers_index, ptx_blob, ptx_hash, prior_tx_hash, prior_ptx_hash);
      if(tvc.m_verifivation_failed) {
        MERROR("Notarization verification failed: " << hash);
      } else if(tvc.m_verifivation_impossible) {
        MERROR("Notarization verification impossible: " << hash);
      }
      if(tvc.m_added_to_pool) {
        MWARNING("Notarization request added: " << hash);
      }
    }
    //relay_ntzpool_transactions();
    return ok;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_stat_info(core_stat_info& st_inf) const
  {
    st_inf.mining_speed = m_miner.get_speed();
    st_inf.alternative_blocks = m_blockchain_storage.get_alternative_blocks_count();
    st_inf.blockchain_height = m_blockchain_storage.get_current_blockchain_height();
    st_inf.tx_pool_size = m_mempool.get_transactions_count();
    st_inf.top_block_id_str = epee::string_tools::pod_to_hex(m_blockchain_storage.get_tail_id());
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_semantic(const transaction& tx, bool keeped_by_block) const
  {
    if(!tx.vin.size())
    {
      MERROR_VER("tx with empty inputs, rejected for tx id= " << get_transaction_hash(tx));
      return false;
    }

    if(!check_inputs_types_supported(tx))
    {
      MERROR_VER("unsupported input types for tx id= " << get_transaction_hash(tx));
      return false;
    }

    if(!check_outs_valid(tx))
    {
      MERROR_VER("tx with invalid outputs, rejected for tx id= " << get_transaction_hash(tx));
      return false;
    }
    if (tx.version >= 1)
    {
      if (tx.rct_signatures.outPk.size() != tx.vout.size())
      {
        MERROR_VER("tx with mismatched vout/outPk count, rejected for tx id= " << get_transaction_hash(tx));
        return false;
      }
    }

    if(!check_money_overflow(tx))
    {
      MERROR_VER("tx has money overflow, rejected for tx id= " << get_transaction_hash(tx));
      return false;
    }

    // for version >= 1, ringct signatures check verifies amounts match

    if(!keeped_by_block && get_object_blobsize(tx) >= m_blockchain_storage.get_current_cumulative_blocksize_limit() - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE)
    {
      MERROR_VER("tx is too large " << get_object_blobsize(tx) << ", expected not bigger than " << m_blockchain_storage.get_current_cumulative_blocksize_limit() - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE);
      return false;
    }

    //check if tx use different key images
    if(!check_tx_inputs_keyimages_diff(tx))
    {
      MERROR_VER("tx uses a single key image more than once");
      return false;
    }

    if (!check_tx_inputs_ring_members_diff(tx))
    {
      MERROR_VER("tx uses duplicate ring members");
      return false;
    }

    if (!check_tx_inputs_keyimages_domain(tx))
    {
      MERROR_VER("tx uses key image not in the valid domain");
      return false;
    }

    if (tx.version >= 1)
    {
      const rct::rctSig &rv = tx.rct_signatures;
      switch (rv.type) {
        case rct::RCTTypeNull:
          // coinbase should not come here, so we reject for all other types
          MERROR_VER("Unexpected Null rctSig type");
          return false;
        case rct::RCTTypeSimple:
        case rct::RCTTypeSimpleBulletproof:
          if (!rct::verRctSimple(rv, true))
          {
            MERROR_VER("rct signature semantics check failed");
            return false;
          }
          break;
        case rct::RCTTypeFull:
        case rct::RCTTypeFullBulletproof:
          if (!rct::verRct(rv, true))
          {
            MERROR_VER("rct signature semantics check failed");
            return false;
          }
          break;
        default:
          MERROR_VER("Unknown rct type: " << rv.type);
          return false;
      }
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::is_key_image_spent(const crypto::key_image &key_image) const
  {
    return m_blockchain_storage.have_tx_keyimg_as_spent(key_image);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::are_key_images_spent(const std::vector<crypto::key_image>& key_im, std::vector<bool> &spent) const
  {
    spent.clear();
    for(auto& ki: key_im)
    {
      spent.push_back(m_blockchain_storage.have_tx_keyimg_as_spent(ki));
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_block_sync_size(uint64_t height) const
  {
    return BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::are_key_images_spent_in_pool(const std::vector<crypto::key_image>& key_im, std::vector<bool> &spent) const
  {
    spent.clear();

    return m_mempool.check_for_key_images(key_im, spent);
  }
  //-----------------------------------------------------------------------------------------------
  std::pair<uint64_t, uint64_t> core::get_coinbase_tx_sum(const uint64_t start_offset, const size_t count)
  {
    uint64_t emission_amount = 0;
    uint64_t total_fee_amount = 0;
    if (count)
    {
      const uint64_t end = start_offset + count - 1;
      m_blockchain_storage.for_blocks_range(start_offset, end,
        [this, &emission_amount, &total_fee_amount](uint64_t, const crypto::hash& hash, const block& b){
      std::list<transaction> txs;
      std::list<crypto::hash> missed_txs;
      uint64_t coinbase_amount = get_outs_money_amount(b.miner_tx);
      this->get_transactions(b.tx_hashes, txs, missed_txs);
      uint64_t tx_fee_amount = 0;
      for(const auto& tx: txs)
      {
        tx_fee_amount += get_tx_fee(tx);
      }

      emission_amount += coinbase_amount - tx_fee_amount;
      total_fee_amount += tx_fee_amount;
      return true;
      });
    }

    return std::pair<uint64_t, uint64_t>(emission_amount, total_fee_amount);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_inputs_keyimages_diff(const transaction& tx) const
  {
    std::unordered_set<crypto::key_image> ki;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if(!ki.insert(tokey_in.k_image).second)
        return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_inputs_ring_members_diff(const transaction& tx) const
  {
    const uint8_t version = m_blockchain_storage.get_current_hard_fork_version();
    if (version >= 1)
    {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
        for (size_t n = 1; n < tokey_in.key_offsets.size(); ++n)
          if (tokey_in.key_offsets[n] == 0)
            return false;
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_inputs_keyimages_domain(const transaction& tx) const
  {
    std::unordered_set<crypto::key_image> ki;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if (!(rct::scalarmultKey(rct::ki2rct(tokey_in.k_image), rct::curveOrder()) == rct::identity()))
        return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_tx(transaction& tx, tx_verification_context& tvc, bool keeped_by_block, bool relayed, bool do_not_relay)
  {
    crypto::hash tx_hash = get_transaction_hash(tx);
    crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);
    blobdata bl;
    t_serializable_object_to_blob(tx, bl);
    return add_new_tx(tx, tx_hash, tx_prefix_hash, bl.size(), tvc, keeped_by_block, relayed, do_not_relay);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_blockchain_total_transactions() const
  {
    return m_blockchain_storage.get_total_transactions();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_tx(transaction& tx, const crypto::hash& tx_hash, const crypto::hash& tx_prefix_hash, size_t blob_size, tx_verification_context& tvc, bool keeped_by_block, bool relayed, bool do_not_relay)
  {
    if(m_mempool.have_tx(tx_hash))
    {
      LOG_PRINT_L2("tx " << tx_hash << "already have transaction in tx_pool");
      return true;
    }

    if(m_blockchain_storage.have_tx(tx_hash))
    {
      LOG_PRINT_L2("tx " << tx_hash << " already have transaction in blockchain");
      return true;
    }

    uint8_t version = m_blockchain_storage.get_current_hard_fork_version();
    return m_mempool.add_tx(tx, tx_hash, blob_size, tvc, keeped_by_block, relayed, do_not_relay, version);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_ntz_req(transaction& tx, const crypto::hash& tx_hash, const crypto::hash& tx_prefix_hash, size_t blob_size, ntz_req_verification_context& tvc, bool keeped_by_block, bool relayed, bool do_not_relay, int const& sig_count, std::string const& signers_str, cryptonote::blobdata const& ptx_blob, crypto::hash const& ptx_hash, crypto::hash const& prior_tx_hash, crypto::hash const& prior_ptx_hash)
  {
    if (m_target_blockchain_height)
    {
      // m_target_height is set to 0 on init, and occassionally in protocol_handler.inl
      if (m_blockchain_storage.get_db().height() < (m_target_blockchain_height - 1))
      {
        LOG_PRINT_L2("Received notarization request while syncing, ignoring until we hit chain tip!");
        return true;
      }
    }

    if(m_mempool.have_tx(tx_hash))
    {
      LOG_PRINT_L2("tx " << tx_hash << "already have transaction in tx_pool");
      return true;
    }

    if (tx.version != (DPOW_NOTA_TX_VERSION))
    {
      MERROR("Encountered ntz sig request with incorrect tx version! Failing validation...");
      return false;
    }

    std::list<int> signers_index;
    int ntz_signer = -1;
    for (int i = 0; i < (DPOW_SIG_COUNT); i++)
    {
      std::string si_tmp = signers_str.substr(i*2, 2);
      int s_ind = std::stoi(si_tmp, nullptr, 10);
      if ((s_ind >= 64) || (s_ind < -1))
      {
        MERROR("Error at core::add_new_tx! signer_index expected value: [-1,63] || actual value: " << si_tmp);
        MERROR("Transaction with issue: " << epee::string_tools::pod_to_hex(get_transaction_hash(tx)));
        return false;
      }
      signers_index.push_back(s_ind);
      if (s_ind != -1)
        ntz_signer = s_ind;
    }

    std::vector<uint8_t> new_extra, new_vec, ntz_data;
    std::string ntz_string_rem;
    int signer_idx_embed = -1;
    remove_ntz_data_from_tx_extra(tx.extra, new_extra, ntz_data, ntz_string_rem, signer_idx_embed);

    if (signer_idx_embed == (-1))
    {
      MERROR("Couldn't extract signer_idx_embed from tx.extra!");
      return false;
    } else {
      if (signer_idx_embed != ntz_signer)
      {
        MERROR("Error: signer_idx_embed and ntz_signer mismatch for tx: " << epee::string_tools::pod_to_hex(get_transaction_hash(tx)));
        return false;
      }
    }

    uint8_t* ntz_data_ptr = ntz_data.data();
    uint8_t has_raw_ntz_data = 0;

    bits256 bits = komodo::bits256_doublesha256(ntz_data_ptr, ntz_data.size());
    for (const auto& each : bits.bytes) {
      new_vec.push_back(each);
    }
    std::string hex_from_bits = bytes256_to_hex(new_vec);
    MWARNING("Bits from doublesha = " << hex_from_bits);

    if (!ntz_string_rem.empty())
      has_raw_ntz_data = 1;

    int neg = -1;
    int count = (DPOW_SIG_COUNT) - std::count(signers_index.begin(), signers_index.end(), neg);
    bool ready = false;
    bool count_check = false;

    count_check = (count == sig_count);
    MWARNING("tx " << tx_hash << " not ready to be sent yet, sig count: " << std::to_string(sig_count));

    if(m_blockchain_storage.have_tx(tx_hash))
    {
      MWARNING("tx " << tx_hash << " already have transaction in blockchain");
      return true;
    }

    uint8_t version = m_blockchain_storage.get_current_hard_fork_version();

    if(!count_check) {
      MERROR("Error: Signature count does not match signer index!");
      return false;
    } else {
      return m_mempool.add_ntz_req(tx, tx_hash, blob_size, tvc, keeped_by_block, relayed, do_not_relay, version, has_raw_ntz_data, sig_count, signers_index, ptx_blob, ptx_hash);
    }
  }
  //-----------------------------------------------------------------------------------------------
  bool core::relay_txpool_transactions()
  {
    // we attempt to relay txes that should be relayed, but were not
    std::list<std::pair<crypto::hash, cryptonote::blobdata>> txs;
    if (m_mempool.get_relayable_transactions(txs) && !txs.empty())
    {
      cryptonote_connection_context fake_context;
      tx_verification_context tvc = AUTO_VAL_INIT(tvc);
      NOTIFY_NEW_TRANSACTIONS::request r;
      for (auto it = txs.begin(); it != txs.end(); ++it)
      {
        r.txs.push_back(it->second);
      }
      get_protocol()->relay_transactions(r, fake_context);
      m_mempool.set_relayed(txs);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::relay_ntzpool_transactions()
  {
    //MWARNING("Called relay_ntzpool_transactions()!");
    std::vector<ntz_tx_info> tx_infos;
    std::vector<spent_key_image_info> key_image_infos;
    get_pending_ntz_pool_and_spent_keys_info(tx_infos, key_image_infos);
    if (!tx_infos.empty()) {
      for (const auto& each : tx_infos)
      {
        cryptonote_connection_context fake_context = AUTO_VAL_INIT(fake_context);
        ntz_req_verification_context tvc = AUTO_VAL_INIT(tvc);
        NOTIFY_REQUEST_NTZ_SIG::request r = AUTO_VAL_INIT(r);
        ntzpool_tx_meta_t meta;
        crypto::hash ntz_hash;
        if (!string_to_hash(each.id_hash, ntz_hash)) {
          return false;
        }
        if (!m_blockchain_storage.get_ntzpool_tx_meta(ntz_hash, meta)) {
          MERROR("Error fetching ntzpool meta in relay_ntzpool_transactions()!");
        }
        r.sig_count = each.sig_count;
        r.tx_hash = ntz_hash;
        r.tx_blob = each.tx_blob;
        crypto::hash ptx_hash;
        if (!string_to_hash(each.ptx_hash, ptx_hash)) {
          return false;
        }
        r.ptx_string = each.ptx_blob;
        std::string signers_index;
        const int neg = -1;
        for (const auto& sig : each.signers_index) {
          std::string tmp;
          if ((sig < 10) && (sig > neg)) {
            tmp = "0" + std::to_string(sig);
          } else {
            tmp = std::to_string(sig);
          }
          signers_index += tmp;
        }

        r.signers_index = signers_index;
        r.ptx_hash = ptx_hash;
        if (get_protocol()->relay_request_ntz_sig(r, fake_context)) {
          std::string logging = epee::string_tools::pod_to_hex(ntz_hash);
          MWARNING("Ntzpool relay successful for transaction: " << logging);
        }
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::flush_ntzpool()
  {
    m_blockchain_storage.flush_ntzpool();
    return;
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_transaction_relayed(const cryptonote::blobdata& tx_blob)
  {
    std::list<std::pair<crypto::hash, cryptonote::blobdata>> txs;
    cryptonote::transaction tx;
    crypto::hash tx_hash, tx_prefix_hash;
    if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash, tx_prefix_hash))
    {
      LOG_ERROR("Failed to parse relayed transaction");
      return;
    }
    txs.push_back(std::make_pair(tx_hash, std::move(tx_blob)));
    m_mempool.set_relayed(txs);
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_ntz_sig_relayed(const cryptonote::blobdata& tx_blob)
  {
    std::list<std::pair<crypto::hash, cryptonote::blobdata>> txs;
    cryptonote::transaction tx;
    crypto::hash tx_hash, tx_prefix_hash;
    if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash, tx_prefix_hash))
    {
      LOG_ERROR("Failed to parse relayed transaction");
      return;
    }
    txs.push_back(std::make_pair(tx_hash, std::move(tx_blob)));
    m_mempool.set_ntz_sig_relayed(txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_template(block& b, const account_public_address& adr, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce)
  {
    return m_blockchain_storage.create_block_template(b, adr, diffic, height, expected_reward, ex_nonce);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const
  {
    return m_blockchain_storage.find_blockchain_supplement(qblock_ids, resp);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, std::list<std::pair<cryptonote::blobdata, std::list<cryptonote::blobdata> > >& blocks, uint64_t& total_height, uint64_t& start_height, size_t max_count) const
  {
    return m_blockchain_storage.find_blockchain_supplement(req_start_block, qblock_ids, blocks, total_height, start_height, max_count);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) const
  {
    return m_blockchain_storage.get_random_outs_for_amounts(req, res);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_outs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const
  {
    return m_blockchain_storage.get_outs(req, res);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_random_rct_outs(const COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::request& req, COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::response& res) const
  {
    return m_blockchain_storage.get_random_rct_outs(req, res);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) const
  {
    return m_blockchain_storage.get_output_distribution(amount, from_height, start_height, distribution, base);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const
  {
    return m_blockchain_storage.get_tx_outputs_gindexs(tx_id, indexs);
  }
  //-----------------------------------------------------------------------------------------------
  void core::pause_mine()
  {
    m_miner.pause();
  }
  //-----------------------------------------------------------------------------------------------
  void core::resume_mine()
  {
    m_miner.resume();
  }
  //-----------------------------------------------------------------------------------------------
  block_complete_entry get_block_complete_entry(block& b, tx_memory_pool &pool)
  {
    block_complete_entry bce;
    bce.block = cryptonote::block_to_blob(b);
    for (const auto &tx_hash: b.tx_hashes)
    {
      cryptonote::blobdata txblob;
      CHECK_AND_ASSERT_THROW_MES(pool.get_transaction(tx_hash, txblob), "Transaction not found in pool");
      bce.txs.push_back(txblob);
    }
    return bce;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_block_found(block& b)
  {
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    m_miner.pause();
    std::list<block_complete_entry> blocks;
    try
    {
      blocks.push_back(get_block_complete_entry(b, m_mempool));
    }
    catch (const std::exception &e)
    {
      m_miner.resume();
      return false;
    }
    bool is_notarizing_block = false;
    prepare_handle_incoming_blocks(blocks);
    m_blockchain_storage.add_new_block(b, bvc, is_notarizing_block);
    cleanup_handle_incoming_blocks(true);
    //anyway - update miner template
    if (is_notarizing_block && bvc.m_added_to_main_chain) {
      m_blockchain_storage.komodo_update();
    }
    update_miner_block_template();
    m_miner.resume();


    CHECK_AND_ASSERT_MES(!bvc.m_verifivation_failed, false, "mined block failed verification");
    if(bvc.m_added_to_main_chain)
    {
      cryptonote_connection_context exclude_context = boost::value_initialized<cryptonote_connection_context>();
      NOTIFY_NEW_BLOCK::request arg = AUTO_VAL_INIT(arg);
      arg.current_blockchain_height = m_blockchain_storage.get_current_blockchain_height();
      std::list<crypto::hash> missed_txs;
      std::list<cryptonote::blobdata> txs;
      m_blockchain_storage.get_transactions_blobs(b.tx_hashes, txs, missed_txs);
      if(missed_txs.size() &&  m_blockchain_storage.get_block_id_by_height(get_block_height(b)) != get_block_hash(b))
      {
        LOG_PRINT_L1("Block found but, seems that reorganize just happened after that, do not relay this block");
        return true;
      }
      CHECK_AND_ASSERT_MES(txs.size() == b.tx_hashes.size() && !missed_txs.size(), false, "can't find some transactions in found block:" << get_block_hash(b) << " txs.size()=" << txs.size()
        << ", b.tx_hashes.size()=" << b.tx_hashes.size() << ", missed_txs.size()" << missed_txs.size());

      block_to_blob(b, arg.b.block);
      //pack transactions
      for(auto& tx:  txs)
        arg.b.txs.push_back(tx);

      m_pprotocol->relay_block(arg, exclude_context);
    }
    return bvc.m_added_to_main_chain;
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_synchronized()
  {
    m_miner.on_synchronized();
  }
  //-----------------------------------------------------------------------------------------------
  void core::safesyncmode(const bool onoff)
  {
    m_blockchain_storage.safesyncmode(onoff);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_block(const block& b, block_verification_context& bvc, bool& is_notarizing_block)
  {
    return m_blockchain_storage.add_new_block(b, bvc, is_notarizing_block);
  }

  //-----------------------------------------------------------------------------------------------
  bool core::prepare_handle_incoming_blocks(const std::list<block_complete_entry> &blocks)
  {
    m_incoming_tx_lock.lock();
    std::list<crypto::hash> txids_to_flush;
    for (const auto& each : blocks) {
      cryptonote::block b;
      if (!parse_and_validate_block_from_blob(each.block, b)) {
        MERROR("Failed to parse and validate block from blob in core::handle_incoming_blocks!");
        break;
      }
      if (get_block_height(b) < get_notarization_wait()) {
        flush_ntzpool();
        std::list<cryptonote::transaction> txs;
        bool include_unrelayed = true;
        m_mempool.get_transactions(txs, include_unrelayed);
        for (const auto& each : txs) {
          if (each.version == (DPOW_NOTA_TX_VERSION)) {  //TODO: consider moving this elsewhere.
                                                         //this much mempool querying will probably slow sync
            crypto::hash txid = get_transaction_hash(each);
            txids_to_flush.push_back(txid);
            //MERROR("Found ntz tx in pool during notarization wait period. Flushing tx: " << epee::string_tools::pod_to_hex(txid));
          }
        }
      }
    }
    m_blockchain_storage.flush_txes_from_pool(txids_to_flush);
    m_blockchain_storage.prepare_handle_incoming_blocks(blocks);
    return true;
  }

  //-----------------------------------------------------------------------------------------------
  bool core::cleanup_handle_incoming_blocks(bool force_sync)
  {
    bool success = false;
    try {
      success = m_blockchain_storage.cleanup_handle_incoming_blocks(force_sync);
    }
    catch (...) {}
    m_incoming_tx_lock.unlock();
    return success;
  }

  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_block(const blobdata& block_blob, block_verification_context& bvc, bool update_miner_blocktemplate)
  {
    TRY_ENTRY();

    // load json checkpoints every 10min/hour respectively,
    // and verify them with respect to what blocks we already have
    CHECK_AND_ASSERT_MES(update_checkpoints(), false, "One or more checkpoints loaded from json conflicted with existing checkpoints.");

    bvc = boost::value_initialized<block_verification_context>();
    if(block_blob.size() > get_max_block_size())
    {
      LOG_PRINT_L1("WRONG BLOCK BLOB, too big size " << block_blob.size() << ", rejected");
      bvc.m_verifivation_failed = true;
      return false;
    }

    block b = AUTO_VAL_INIT(b);
    if(!parse_and_validate_block_from_blob(block_blob, b))
    {
      LOG_PRINT_L1("Failed to parse and validate new block");
      bvc.m_verifivation_failed = true;
      return false;
    }
    bool is_notarizing_block = false;
    add_new_block(b, bvc, is_notarizing_block);
    if (bvc.m_added_to_main_chain) {
      if (update_miner_blocktemplate) {
        update_miner_block_template();
      }
      if (is_notarizing_block) {
        m_blockchain_storage.komodo_update();
      }
    }
    return true;

    CATCH_ENTRY_L0("core::handle_incoming_block()", false);
  }
  //-----------------------------------------------------------------------------------------------
  // Used by the RPC server to check the size of an incoming
  // block_blob
  bool core::check_incoming_block_size(const blobdata& block_blob) const
  {
    if(block_blob.size() > get_max_block_size())
    {
      LOG_PRINT_L1("WRONG BLOCK BLOB, too big size " << block_blob.size() << ", rejected");
      return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_tail_id() const
  {
    return m_blockchain_storage.get_tail_id();
  }
  //-----------------------------------------------------------------------------------------------
  difficulty_type core::get_block_cumulative_difficulty(uint64_t height) const
  {
    return m_blockchain_storage.get_db().get_block_cumulative_difficulty(height);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_pool_transactions_count() const
  {
    return m_mempool.get_transactions_count();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::have_block(const crypto::hash& id) const
  {
    return m_blockchain_storage.have_block(id);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::parse_tx_from_blob(transaction& tx, crypto::hash& tx_hash, crypto::hash& tx_prefix_hash, const blobdata& blob) const
  {
    return parse_and_validate_tx_from_blob(blob, tx, tx_hash, tx_prefix_hash);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_syntax(const transaction& tx) const
  {
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transactions(std::list<transaction>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_transactions(txs, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_ntzpool_transactions(std::list<std::pair<transaction,blobdata>>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_pending_ntz_pool_transactions(txs, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_ntzpool_tx_count(size_t& count, bool include_sensitive_data) const
  {
    count = m_mempool.get_ntzpool_transactions_count(include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::flush_ntzpool_txs(std::list<crypto::hash> const& hash_list)
  {
    return m_blockchain_storage.flush_ntz_txes_from_pool(hash_list);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction_hashes(std::vector<crypto::hash>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_transaction_hashes(txs, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction_stats(struct txpool_stats& stats, bool include_sensitive_data) const
  {
    m_mempool.get_transaction_stats(stats, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pending_ntz_pool_transactions(std::list<std::pair<transaction,blobdata>>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_pending_ntz_pool_transactions(txs, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pending_ntz_pool_hashes(std::vector<crypto::hash>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_pending_ntzpool_transaction_hashes(txs, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pending_ntz_pool_stats(struct txpool_stats& stats, bool include_sensitive_data) const
  {
    m_mempool.get_transaction_stats(stats, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction(const crypto::hash &id, cryptonote::blobdata& tx) const
  {
    return m_mempool.get_transaction(id, tx);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_ntzpool_transaction(const crypto::hash &id, cryptonote::blobdata& tx, cryptonote::blobdata& ptx_blob) const
  {
    return m_mempool.get_transaction(id, tx);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::pool_has_tx(const crypto::hash &id) const
  {
    return m_mempool.have_tx(id);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transactions_and_spent_keys_info(std::vector<tx_info>& tx_infos, std::vector<spent_key_image_info>& key_image_infos, bool include_sensitive_data) const
  {
    return m_mempool.get_transactions_and_spent_keys_info(tx_infos, key_image_infos, include_sensitive_data);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pending_ntz_pool_and_spent_keys_info(std::vector<ntz_tx_info>& tx_infos, std::vector<spent_key_image_info>& key_image_infos, bool include_sensitive_data) const
  {
    return m_mempool.get_pending_ntzpool_and_spent_keys_info(tx_infos, key_image_infos, include_sensitive_data);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_for_rpc(std::vector<cryptonote::rpc::tx_in_pool>& tx_infos, cryptonote::rpc::key_images_with_tx_hashes& key_image_infos) const
  {
    return m_mempool.get_pool_for_rpc(tx_infos, key_image_infos);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_ntzpool_for_rpc(std::vector<cryptonote::rpc::tx_in_ntzpool>& tx_infos, cryptonote::rpc::key_images_with_tx_hashes& key_image_infos) const
  {
    return m_mempool.get_ntzpool_for_rpc(tx_infos, key_image_infos);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_short_chain_history(std::list<crypto::hash>& ids) const
  {
    return m_blockchain_storage.get_short_chain_history(ids);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp, cryptonote_connection_context& context)
  {
    return m_blockchain_storage.handle_get_objects(arg, rsp);
  }
  //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_block_id_by_height(uint64_t height) const
  {
    return m_blockchain_storage.get_block_id_by_height(height);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
  {
    return m_blockchain_storage.get_block_by_hash(h, blk, orphan);
  }
  //-----------------------------------------------------------------------------------------------
  std::string core::print_pool(bool short_format) const
  {
    return m_mempool.print_pool(short_format);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::update_miner_block_template()
  {
    m_miner.on_block_chain_update();
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::on_idle()
  {
    if(!m_starter_message_showed)
    {
      std::string main_message;
      if (m_offline)
        main_message = "The daemon is running offline and will not attempt to sync to the BLUR network.";
      else
        main_message = "The daemon will start synchronizing with the network. This may take a long time to complete.";
      MGINFO_YELLOW(ENDL << "**********************************************************************" << ENDL
        << main_message << ENDL
        << ENDL
        << "You can set the level of process detailization through \"set_log <level|categories>\" command," << ENDL
        << "where <level> is between 0 (no details) and 4 (very verbose), or custom category based levels (eg, *:WARNING)." << ENDL
        << ENDL
        << "Use the \"help\" command to see the list of available commands." << ENDL
        << "Use \"help <command>\" to see a command's documentation." << ENDL
        << "**********************************************************************" << ENDL);
      m_starter_message_showed = true;
    }

    m_txpool_auto_relayer.do_call(boost::bind(&core::relay_txpool_transactions, this));
    m_check_disk_space_interval.do_call(boost::bind(&core::check_disk_space, this));
    m_miner.on_idle();
    m_mempool.on_idle();
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_fork_time()
  {
    HardFork::State state = m_blockchain_storage.get_hard_fork_state();
    const el::Level level = el::Level::Warning;
    switch (state) {
      case HardFork::LikelyForked:
        MCLOG_RED(level, "global", "**********************************************************************");
        MCLOG_RED(level, "global", "Last scheduled hard fork is too far in the past.");
        MCLOG_RED(level, "global", "We are most likely forked from the network. Daemon update needed now.");
        MCLOG_RED(level, "global", "**********************************************************************");
        break;
      case HardFork::UpdateNeeded:
        MCLOG_RED(level, "global", "**********************************************************************");
        MCLOG_RED(level, "global", "Last scheduled hard fork time shows a daemon update is needed soon.");
        MCLOG_RED(level, "global", "**********************************************************************");
        break;
      default:
        break;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  uint8_t core::get_ideal_hard_fork_version() const
  {
    return get_blockchain_storage().get_ideal_hard_fork_version();
  }
  //-----------------------------------------------------------------------------------------------
  uint8_t core::get_ideal_hard_fork_version(uint64_t height) const
  {
    return get_blockchain_storage().get_ideal_hard_fork_version(height);
  }
  //-----------------------------------------------------------------------------------------------
  uint8_t core::get_hard_fork_version(uint64_t height) const
  {
    return get_blockchain_storage().get_hard_fork_version(height);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_disk_space()
  {
    uint64_t free_space = get_free_space();
    if (free_space < 1ull * 1024 * 1024 * 1024) // 1 GB
    {
      const el::Level level = el::Level::Warning;
      MCLOG_RED(level, "global", "Free space is below 1 GB on " << m_config_folder);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::set_target_blockchain_height(uint64_t target_blockchain_height)
  {
    m_target_blockchain_height = target_blockchain_height;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_target_blockchain_height() const
  {
    return m_target_blockchain_height;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::prevalidate_block_hashes(uint64_t height, const std::list<crypto::hash> &hashes)
  {
    return get_blockchain_storage().prevalidate_block_hashes(height, hashes);
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_free_space() const
  {
    boost::filesystem::path path(m_config_folder);
    boost::filesystem::space_info si = boost::filesystem::space(path);
    return si.available;
  }
  //-----------------------------------------------------------------------------------------------
  std::time_t core::get_start_time() const
  {
    return start_time;
  }
  //-----------------------------------------------------------------------------------------------
  void core::graceful_exit()
  {
    raise(SIGTERM);
  }
}
