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

#include <unordered_set>
#include <random>
#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include "common/apply_permutation.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/miner.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "komodo/komodo_validation.h"
#include "ringct/rctSigs.h"
#include "multisig/multisig.h"
#include "libhydrogen/hydrogen.h"
#include "komodo_notaries.h"
#include "common/hex_str.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace crypto;

namespace cryptonote
{
  //---------------------------------------------------------------
  void classify_addresses(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr, size_t &num_stdaddresses, size_t &num_subaddresses, account_public_address &single_dest_subaddress)
  {
    num_stdaddresses = 0;
    num_subaddresses = 0;
    std::unordered_set<cryptonote::account_public_address> unique_dst_addresses;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      if (change_addr && dst_entr.addr == change_addr)
        continue;
      if (unique_dst_addresses.count(dst_entr.addr) == 0)
      {
        unique_dst_addresses.insert(dst_entr.addr);
        if (dst_entr.is_subaddress)
        {
          ++num_subaddresses;
          single_dest_subaddress = dst_entr.addr;
        }
        else
        {
          ++num_stdaddresses;
        }
      }
    }
    LOG_PRINT_L2("destinations include " << num_stdaddresses << " standard addresses and " << num_subaddresses << " subaddresses");
  }
  //---------------------------------------------------------------
  bool auth_and_get_ntz_signer_index(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr, size_t &num_stdaddresses, account_keys const & sender_account_keys, int& signer_index) {
    num_stdaddresses = 0;
    std::unordered_set<cryptonote::account_public_address> unique_dst_addresses;
    crypto::public_key account_pub_key = crypto::null_pkey;
    bool r = secret_key_to_public_key(sender_account_keys.m_spend_secret_key, account_pub_key);
    if (!r)
    {
      MERROR("Failed to derive public key from secret spend key!");
      return false;
    }
//    MWARNING("In auth_ntz, account_pub_key = " << epee::string_tools::pod_to_hex(account_pub_key));
    hw::device &hwdev = sender_account_keys.get_device();
    bool found_pubkey = false;
    bool pubkey_check = false;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      if (unique_dst_addresses.count(dst_entr.addr) == 0)
      {
        unique_dst_addresses.insert(dst_entr.addr);
        if (dst_entr.is_subaddress)
        {
          MERROR("Notarization tx's cannot be created with subaddress destinations!");
          return false;
        }
        else
        {
          ++num_stdaddresses;
        }
      }
      if (epee::string_tools::pod_to_hex(dst_entr.addr.m_spend_public_key) == epee::string_tools::pod_to_hex(account_pub_key))
      {
        found_pubkey = true;
        LOG_PRINT_L2("Found our public spend key in destinations, marking as found.");
        std::vector<std::pair<crypto::public_key,crypto::public_key>> keys_vec;
        if (!get_notary_pubkeys(keys_vec)) {
          MERROR("Failed to populate vector for notary pubkeys from hardcoded keys!");
          return false;
        } else {
          for (int i = 0; i <= 63; i++) {
            if (epee::string_tools::pod_to_hex(account_pub_key) == epee::string_tools::pod_to_hex(keys_vec[i].second)) {
              pubkey_check = true;
              signer_index = i;
            }
          }
        }
      }
    }

    if (!found_pubkey) {
      MERROR("Failed to find our pubkey in the destinations list! Failed to authenticate.");
      return false;
    }
    if (!pubkey_check) {
      MERROR("Our public key does not match any of those found in the hardcoded notaries list! Failed to authenticate.");
      return false;
    }
      if (found_pubkey && pubkey_check) {
        LOG_PRINT_L2("destinations include " << num_stdaddresses << " standard addresses");
      }
   return (found_pubkey && pubkey_check);
  }
  //---------------------------------------------------------------
  bool construct_miner_tx(size_t height, size_t median_size, uint64_t already_generated_coins, size_t current_block_size, uint64_t fee, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce, size_t max_outs, uint8_t hard_fork_version) {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();

    keypair txkey = keypair::generate(hw::get_device("default"));
    add_tx_pub_key_to_extra(tx, txkey.pub);
    if(!extra_nonce.empty())
      if(!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
        return false;

    txin_gen in;
    in.height = height;

    uint64_t block_reward;
    if(!get_block_reward(median_size, current_block_size, already_generated_coins, block_reward, hard_fork_version))
    {
      LOG_PRINT_L0("Block is too big");
      return false;
    }

#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    LOG_PRINT_L1("Creating block template: reward " << block_reward <<
      ", fee " << fee);
#endif
    block_reward += fee;

    crypto::key_derivation derivation = AUTO_VAL_INIT(derivation);;
    crypto::public_key out_eph_public_key = AUTO_VAL_INIT(out_eph_public_key);
    bool r = crypto::generate_key_derivation(miner_address.m_view_public_key, txkey.sec, derivation);
    CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to generate_key_derivation(" << miner_address.m_view_public_key << ", " << txkey.sec << ")");

    r = crypto::derive_public_key(derivation, 0, miner_address.m_spend_public_key, out_eph_public_key);
    CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to derive_public_key(" << derivation << ", " << miner_address.m_spend_public_key << ")");

    txout_to_key tk;
    tk.key = out_eph_public_key;

    tx_out out;
    out.amount = block_reward;
    out.target = tk;
    tx.vout.push_back(out);

    tx.version = CURRENT_TRANSACTION_VERSION;

    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);

    tx.invalidate_hashes();

    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);
    return true;
  }
  //---------------------------------------------------------------
  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr)
  {
    account_public_address addr = {null_pkey, null_pkey};
    size_t count = 0;
    for (const auto &i : destinations)
    {
      if (i.amount == 0)
        continue;
      if (change_addr && i.addr == *change_addr)
        continue;
      if (i.addr == addr)
        continue;
      if (count > 0)
        return null_pkey;
      addr = i.addr;
      ++count;
    }
    if (count == 0 && change_addr)
      return change_addr->m_view_public_key;
    return addr.m_view_public_key;
  }
  //---------------------------------------------------------------
  bool construct_tx_with_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, std::vector<uint8_t> extra, transaction& tx, uint64_t unlock_time, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, bool rct, bool bulletproof, rct::multisig_out *msout)
  {
    hw::device &hwdev = sender_account_keys.get_device();

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    std::vector<rct::key> amount_keys;
    tx.set_null();
    amount_keys.clear();
    if (msout)
    {
      msout->c.clear();
    }

    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;

    tx.version = CURRENT_TRANSACTION_VERSION;
    tx.unlock_time = unlock_time;

    tx.extra = extra;
    crypto::public_key txkey_pub;


    // if we have a stealth payment id, find it and encrypt it with the tx key now
    std::vector<tx_extra_field> tx_extra_fields;
   /* std::vector<uint8_t> new_extra;
    std::vector<uint8_t> ntz_data;
    std::string ntz_string_rem;
    remove_ntz_data_from_tx_extra(tx.extra, new_extra, ntz_data, ntz_string_rem);
    tx.extra.clear();
    for (const auto& each: new_extra) {
      tx.extra.push_back(each);
    }*/
    if (parse_tx_extra(tx.extra, tx_extra_fields))
    {
      tx_extra_nonce extra_nonce;
      if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
      {
        crypto::hash8 payment_id = null_hash8;
        if (get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
        {
          LOG_PRINT_L2("Encrypting payment id " << payment_id);
          crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
          if (view_key_pub == null_pkey)
          {
            LOG_ERROR("Destinations have to have exactly one output to support encrypted payment ids");
            return false;
          }

          if (!hwdev.encrypt_payment_id(payment_id, view_key_pub, tx_key))
          {
            LOG_ERROR("Failed to encrypt payment id");
            return false;
          }

          std::string extra_nonce;
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
          remove_field_from_tx_extra(tx.extra, typeid(tx_extra_nonce));
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add encrypted payment id to tx extra");
            return false;
          }
          LOG_PRINT_L1("Encrypted payment ID: " << payment_id);
        }
      }
    }
    else
    {
      LOG_ERROR("Failed to parse tx extra");
      return false;
    }
/*     bool empty = ntz_string_rem.empty();
     const std::string ntz = "010000000dd42b2132cc0f6bea63ad6e94015e5fd988ea0370c519fb04aa3c91afac1cc90a0100000048473044022037abbb3ced70a8cd9c2f5c5dea1f4484140aa189b8911bd76340941462ecd4cd0220646879ec97649d121c6d7bcd1714f5a5cbe050216249eea0d94a7029791a8c8c01ffffffff4f2cb08342da314fac56bb95a1b5bb8f7c7f9505026e7f065a8049a568f6bf0b060000004847304402200c8f0746c945c4b72c2115049be8ccd184971ded8f35ffb6557aa5c85823889502204f5a1f3c9484967d98284c7c4511c9c61345159462c2c070d6b45e0d8fc07cc601ffffffff6c70688f390a33b5b10892e0a889670637543563d1ee0e54c8643f80d57be4fe06000000484730440220627db25375a00b939105a7afd0cacf20877d5dfc4d9205e27ab6ba189bdb3f5402201d5969f6ca779838d62c07f8d9c54ff940fe4eb5efc5847ceb4877ec02e1980801ffffffffbe5ff4358913fb0f357cd4f209eccfad53125dd0ed3c50a59c3811c9057ceb430600000049483045022100f452d8a6c70003c930d82f2540851ca18e83beb10a615bd4cc191b9e9df7d81902202457380fdfa79a8ce047ce7bf714d4f8dc1a2c4c9ab6d2a946b05ec6ad57af6f01ffffffff06f2556fe6339b4cd8fcb89b5d180ea1f83d1ebbf773a4fa97ae5aaa4e67cd60050000004847304402203a3fa35b169d7d1b23c63bf16d934e87154b3acdf43bffdeea9bcd711528c06202200592932c1882f19d97cf83bfc40453c5fe4bd91b0bc38f6068421546ba0b38a501ffffffff84a1ab93a653f5c5b005dafb66f04a0e141861d1d119f6373a0df5568ae3e32d030000004948304502210092d29c1689ff36acb43a6b9838820b4424449287e1eea8a2f591d8f9b9f59a89022063b9e87612a1b7489e4b50d9aed00c9c6373cc7abf041280561850c1b292756d01ffffffffb050ff20ccdbdc700cf3187ebe55d2d9919757638d5e1fa384bc36aaddc29a87000000004847304402200214c129a4182e9ffe71e627315e1dce1b660c49b5004652e7b230a4acc95b9e02204b6f66e0346b587a997b0f8571ca54641ca7995d60aef0a2ebdd353b8367958301ffffffff511bf19814deef29ee88b7a94cc936ae0981319df64605b4ff437746daca7f510900000049483045022100808b3bd26a837ee410e69ceb55b7b29e92833ee449467ca4b2922f5195028f3d022011680ccd601451667ba12ed9443124dc565ab67094aa2cf3d0cc0c67560ce0de01ffffffffb67bdcb7c7f7bc1279cfd085d44635ae7011fd529b1d549327d5ff731ff8fbd607000000484730440220379be20435df02115bedd84f1c5ef0c3b1a09f759e63c437e5879ab808bbc60a022009323b553e6fa48f4f56ea3c581549d7179a6b3d2b46f973d939d5cea6c1613701ffffffff6732d747a48663467d21c4282fb6705f3916421912ec4312ccf3cc6258933e35040000004847304402206f0e939e09a0ccb4d746663e15091aaa5ea64699b8f2faa515c079f41a0f2b4c02204dc5d887f6fc70c6488c644e6adc7e749fd0cbb5195eb986704e486a8a31ec3101ffffffff611904eeb777c1f1c86262fa7f8e3191a2125ee4c8440837e5b8604144dcb526090000004847304402206ec15a69e81569b606b550a7af9530172923c6933a6832608d8fb8f8cf9067ba0220136f0aaa4790e9120da876fa2cfa963b96d2774026c0f803d0924a6cefbf3d0e01fffffffff0300247cd2234bcffd923895b579cf7fbcba5405df5f09c468da835cc416e9005000000484730440220119ee524eae3810da16132e1e9aeb28f23ad81780389808124897f4ebfbacee302205204643fbccbd8befb5d1b71dbcca4a44b6ef0b32fcc894b3fed76ccfc6bd7c601ffffffffa377c825ea5a03dc93c93a41ac06f58042512d5098333574d6de0d8a6d5b99820700000049483045022100ad752b6d0ab189bc1a267008816d8cac4982823dc20a60967a078dc9ed17348e022066c4779c21f706ee3c4aa0f956e0d2a746c2cfb587550c07c5a6a2385c1f3ebf01ffffffff02b0890700000000002321020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9ac00000000000000002a6a28071c4524afe8cf8e412b6fdb06e65795839f189205119294d26939c61c37880a084409004b4d440000000000";
     bool z = add_ntz_txn_to_extra(tx.extra, empty ? ntz : ntz_string_rem);
     if (!z) {
       MERROR("Failed to add ntz_tx data to extra!");
       return false;
     }*/

    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
    struct input_generation_context_data
    {
      keypair in_ephemeral;
    };
    std::vector<input_generation_context_data> in_contexts;

    uint64_t summary_inputs_money = 0;
    //fill inputs
    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.outputs.size())
      {
        LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
        return false;
      }
      summary_inputs_money += src_entr.amount;

      //key_derivation recv_derivation;
      in_contexts.push_back(input_generation_context_data());
      keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      crypto::key_image img;
      const auto& out_key = reinterpret_cast<const crypto::public_key&>(src_entr.outputs[src_entr.real_output].second.dest);
      if(!generate_key_image_helper(sender_account_keys, subaddresses, out_key, src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys, src_entr.real_output_in_tx_index, in_ephemeral,img, hwdev))
      {
        LOG_ERROR("Key image generation failed!");
        return false;
      }

      //check that derivated key is equal with real output key (if non multisig)
      if(!msout && !(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< ENDL << "derived_key:"
          << string_tools::pod_to_hex(in_ephemeral.pub) << ENDL << "real output_public_key:"
          << string_tools::pod_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
        LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      //put key image into tx input
      txin_to_key input_to_key;
      input_to_key.amount = src_entr.amount;
      input_to_key.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;

      //fill outputs array and use relative offsets
      for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
        input_to_key.key_offsets.push_back(out_entry.first);

      input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
      tx.vin.push_back(input_to_key);
    }

    // "Shuffle" outs
    std::vector<tx_destination_entry> shuffled_dsts(destinations);
    std::random_shuffle(shuffled_dsts.begin(), shuffled_dsts.end(), [](unsigned int i) { return crypto::rand<unsigned int>() % i; });

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    if (num_stdaddresses == 0 && num_subaddresses == 1)
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(single_dest_subaddress.m_spend_public_key), rct::sk2rct(tx_key)));
    }
    else
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
    }
    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
    add_tx_pub_key_to_extra(tx, txkey_pub);

    std::vector<crypto::public_key> additional_tx_public_keys;
    // we don't need to include additional tx keys if:
    //   - all the destinations are standard addresses
    //   - there's only one destination which is a subaddress
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    bool additional_tx_keys_present = additional_tx_public_keys.size() > 0;
    if (need_additional_txkeys || (!need_additional_txkeys && additional_tx_keys_present))
      CHECK_AND_ASSERT_MES(destinations.size() == additional_tx_keys.size(), false, "Wrong amount of additional tx keys");

    uint64_t summary_outs_money = 0;
    //fill outputs
    size_t output_index = 0;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      crypto::key_derivation derivation;
      crypto::public_key out_eph_public_key;

      // make additional tx pubkey if necessary
      keypair additional_txkey;
      if (need_additional_txkeys || (!need_additional_txkeys && additional_tx_keys_present))
      {
        additional_txkey.sec = additional_tx_keys[output_index];
        if (dst_entr.is_subaddress)
          additional_txkey.pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(dst_entr.addr.m_spend_public_key), rct::sk2rct(additional_txkey.sec)));
        else
          additional_txkey.pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(additional_txkey.sec)));
      }

      bool r;
      if (change_addr && dst_entr.addr == *change_addr)
      {
        // sending change to yourself; derivation = a*R
        r = hwdev.generate_key_derivation(txkey_pub, sender_account_keys.m_view_secret_key, derivation);
        CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to generate_key_derivation(" << txkey_pub << ", " << sender_account_keys.m_view_secret_key << ")");
      }
      else
      {
        // sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
        r = hwdev.generate_key_derivation(dst_entr.addr.m_view_public_key, dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key, derivation);
        CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to generate_key_derivation(" << dst_entr.addr.m_view_public_key << ", " << (dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key) << ")");
      }

      if (need_additional_txkeys)
      {
        additional_tx_public_keys.push_back(additional_txkey.pub);
      }
      else if (additional_tx_keys_present)
      {
        additional_tx_public_keys.push_back(additional_txkey.pub);
      }

      if (tx.version >= 1)
      {
        crypto::secret_key scalar1;
        hwdev.derivation_to_scalar(derivation, output_index, scalar1);
        amount_keys.push_back(rct::sk2rct(scalar1));
      }
      r = hwdev.derive_public_key(derivation, output_index, dst_entr.addr.m_spend_public_key, out_eph_public_key);
      CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to derive_public_key(" << derivation << ", " << output_index << ", "<< dst_entr.addr.m_spend_public_key << ")");

      hwdev.add_output_key_mapping(dst_entr.addr.m_view_public_key, dst_entr.addr.m_spend_public_key, dst_entr.is_subaddress, output_index, amount_keys.back(), out_eph_public_key);

      tx_out out;
      out.amount = dst_entr.amount;
      txout_to_key tk;
      tk.key = out_eph_public_key;
      out.target = tk;
      tx.vout.push_back(out);
      output_index++;
      summary_outs_money += dst_entr.amount;
    }
    CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");

    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_additional_pub_keys));

    LOG_PRINT_L2("tx pubkey: " << txkey_pub);
    if (need_additional_txkeys || (!need_additional_txkeys && additional_tx_keys_present))
    {
      LOG_PRINT_L2("additional tx pubkeys: ");
      for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
        LOG_PRINT_L2(additional_tx_public_keys[i]);
      add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
    }

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return false;
    }

    // check for watch only wallet
    bool zero_secret_key = true;
    for (size_t i = 0; i < sizeof(sender_account_keys.m_spend_secret_key); ++i)
      zero_secret_key &= (sender_account_keys.m_spend_secret_key.data[i] == 0);
    if (zero_secret_key)
    {
      MDEBUG("Null secret key, skipping signatures");
    }

    if (tx.version >= 1)
    {
      size_t n_total_outs = sources[0].outputs.size(); // only for non-simple rct

      // the non-simple version is slightly smaller, but assumes all real inputs
      // are on the same index, so can only be used if there just one ring.
      bool use_simple_rct = sources.size() > 1;

      if (!use_simple_rct)
      {
        // non simple ringct requires all real inputs to be at the same index for all inputs
        for(const tx_source_entry& src_entr:  sources)
        {
          if(src_entr.real_output != sources.begin()->real_output)
          {
            LOG_ERROR("All inputs must have the same index for non-simple ringct");
            return false;
          }
        }

        // enforce same mixin for all outputs
        for (size_t i = 1; i < sources.size(); ++i) {
          if (n_total_outs != sources[i].outputs.size()) {
            LOG_ERROR("Non-simple ringct transaction has varying ring size");
            return false;
          }
        }
      }

      uint64_t amount_in = 0, amount_out = 0;
      rct::ctkeyV inSk;
      inSk.reserve(sources.size());
      // mixRing indexing is done the other way round for simple
      rct::ctkeyM mixRing(use_simple_rct ? sources.size() : n_total_outs);
      rct::keyV destinations;
      std::vector<uint64_t> inamounts, outamounts;
      std::vector<unsigned int> index;
      std::vector<rct::multisig_kLRki> kLRki;
      for (size_t i = 0; i < sources.size(); ++i)
      {
        rct::ctkey ctkey;
        amount_in += sources[i].amount;
        inamounts.push_back(sources[i].amount);
        index.push_back(sources[i].real_output);
        // inSk: (secret key, mask)
        ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
        ctkey.mask = sources[i].mask;
        inSk.push_back(ctkey);
        memwipe(&ctkey, sizeof(rct::ctkey));
        // inPk: (public key, commitment)
        // will be done when filling in mixRing
        if (msout)
        {
          kLRki.push_back(sources[i].multisig_kLRki);
        }
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        destinations.push_back(rct::pk2rct(boost::get<txout_to_key>(tx.vout[i].target).key));
        outamounts.push_back(tx.vout[i].amount);
        amount_out += tx.vout[i].amount;
      }

      if (use_simple_rct)
      {
        // mixRing indexing is done the other way round for simple
        for (size_t i = 0; i < sources.size(); ++i)
        {
          mixRing[i].resize(sources[i].outputs.size());
          for (size_t n = 0; n < sources[i].outputs.size(); ++n)
          {
            mixRing[i][n] = sources[i].outputs[n].second;
          }
        }
      }
      else
      {
        for (size_t i = 0; i < n_total_outs; ++i) // same index assumption
        {
          mixRing[i].resize(sources.size());
          for (size_t n = 0; n < sources.size(); ++n)
          {
            mixRing[i][n] = sources[n].outputs[i].second;
          }
        }
      }

      // fee
      if (!use_simple_rct && amount_in > amount_out)
        outamounts.push_back(amount_in - amount_out);

      // zero out all amounts to mask rct outputs, real amounts are now encrypted
      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (sources[i].rct)
          boost::get<txin_to_key>(tx.vin[i]).amount = 0;
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
        tx.vout[i].amount = 0;

      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash);
      rct::ctkeyV outSk;
      if (use_simple_rct)
        tx.rct_signatures = rct::genRctSimple(rct::hash2rct(tx_prefix_hash), inSk, destinations, inamounts, outamounts, amount_in - amount_out, mixRing, amount_keys, msout ? &kLRki : NULL, msout, index, outSk, bulletproof, hwdev);
      else
        tx.rct_signatures = rct::genRct(rct::hash2rct(tx_prefix_hash), inSk, destinations, outamounts, mixRing, amount_keys, msout ? &kLRki[0] : NULL, msout, sources[0].real_output, outSk, bulletproof, hwdev); // same index assumption
      memwipe(inSk.data(), inSk.size() * sizeof(rct::ctkey));

      CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);
    }

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_ntz_tx_with_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, std::vector<uint8_t> extra, transaction& tx, uint64_t unlock_time, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, bool rct, bool bulletproof, rct::multisig_out *msout)
  {
    hw::device &hwdev = sender_account_keys.get_device();

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    std::vector<rct::key> amount_keys;
    tx.set_null();
    amount_keys.clear();
    if (msout)
    {
      msout->c.clear();
    }
    int signer_index = -1;
    bool auth = false;

    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);

    auth = auth_and_get_ntz_signer_index(destinations, change_addr, num_stdaddresses, sender_account_keys, signer_index);

    tx.version = (auth && (num_subaddresses = 0) && (signer_index > 0) && (signer_index < 64))  ? 2 : CURRENT_TRANSACTION_VERSION;
    tx.unlock_time = unlock_time;

    tx.extra = extra;
    crypto::public_key txkey_pub;

    // if we have a stealth payment id, find it and encrypt it with the tx key now
    std::vector<tx_extra_field> tx_extra_fields;
   /* std::vector<uint8_t> new_extra;
    std::vector<uint8_t> ntz_data;
    std::string ntz_string_rem;
    remove_ntz_data_from_tx_extra(tx.extra, new_extra, ntz_data, ntz_string_rem);
    tx.extra.clear();
    for (const auto& each: new_extra) {
      tx.extra.push_back(each);
    }*/
    if (parse_tx_extra(tx.extra, tx_extra_fields))
    {
      tx_extra_nonce extra_nonce;
      if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
      {
        crypto::hash8 payment_id = null_hash8;
        if (get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
        {
          LOG_PRINT_L2("Encrypting payment id " << payment_id);
          crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
          if (view_key_pub == null_pkey)
          {
            LOG_ERROR("Destinations have to have exactly one output to support encrypted payment ids");
            return false;
          }

          if (!hwdev.encrypt_payment_id(payment_id, view_key_pub, tx_key))
          {
            LOG_ERROR("Failed to encrypt payment id");
            return false;
          }

          std::string extra_nonce;
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
          remove_field_from_tx_extra(tx.extra, typeid(tx_extra_nonce));
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add encrypted payment id to tx extra");
            return false;
          }
          LOG_PRINT_L1("Encrypted payment ID: " << payment_id);
        }
      }
    }
    else
    {
      LOG_ERROR("Failed to parse tx extra");
      return false;
    }
/*     bool empty = ntz_string_rem.empty();
     const std::string ntz = "010000000dd42b2132cc0f6bea63ad6e94015e5fd988ea0370c519fb04aa3c91afac1cc90a0100000048473044022037abbb3ced70a8cd9c2f5c5dea1f4484140aa189b8911bd76340941462ecd4cd0220646879ec97649d121c6d7bcd1714f5a5cbe050216249eea0d94a7029791a8c8c01ffffffff4f2cb08342da314fac56bb95a1b5bb8f7c7f9505026e7f065a8049a568f6bf0b060000004847304402200c8f0746c945c4b72c2115049be8ccd184971ded8f35ffb6557aa5c85823889502204f5a1f3c9484967d98284c7c4511c9c61345159462c2c070d6b45e0d8fc07cc601ffffffff6c70688f390a33b5b10892e0a889670637543563d1ee0e54c8643f80d57be4fe06000000484730440220627db25375a00b939105a7afd0cacf20877d5dfc4d9205e27ab6ba189bdb3f5402201d5969f6ca779838d62c07f8d9c54ff940fe4eb5efc5847ceb4877ec02e1980801ffffffffbe5ff4358913fb0f357cd4f209eccfad53125dd0ed3c50a59c3811c9057ceb430600000049483045022100f452d8a6c70003c930d82f2540851ca18e83beb10a615bd4cc191b9e9df7d81902202457380fdfa79a8ce047ce7bf714d4f8dc1a2c4c9ab6d2a946b05ec6ad57af6f01ffffffff06f2556fe6339b4cd8fcb89b5d180ea1f83d1ebbf773a4fa97ae5aaa4e67cd60050000004847304402203a3fa35b169d7d1b23c63bf16d934e87154b3acdf43bffdeea9bcd711528c06202200592932c1882f19d97cf83bfc40453c5fe4bd91b0bc38f6068421546ba0b38a501ffffffff84a1ab93a653f5c5b005dafb66f04a0e141861d1d119f6373a0df5568ae3e32d030000004948304502210092d29c1689ff36acb43a6b9838820b4424449287e1eea8a2f591d8f9b9f59a89022063b9e87612a1b7489e4b50d9aed00c9c6373cc7abf041280561850c1b292756d01ffffffffb050ff20ccdbdc700cf3187ebe55d2d9919757638d5e1fa384bc36aaddc29a87000000004847304402200214c129a4182e9ffe71e627315e1dce1b660c49b5004652e7b230a4acc95b9e02204b6f66e0346b587a997b0f8571ca54641ca7995d60aef0a2ebdd353b8367958301ffffffff511bf19814deef29ee88b7a94cc936ae0981319df64605b4ff437746daca7f510900000049483045022100808b3bd26a837ee410e69ceb55b7b29e92833ee449467ca4b2922f5195028f3d022011680ccd601451667ba12ed9443124dc565ab67094aa2cf3d0cc0c67560ce0de01ffffffffb67bdcb7c7f7bc1279cfd085d44635ae7011fd529b1d549327d5ff731ff8fbd607000000484730440220379be20435df02115bedd84f1c5ef0c3b1a09f759e63c437e5879ab808bbc60a022009323b553e6fa48f4f56ea3c581549d7179a6b3d2b46f973d939d5cea6c1613701ffffffff6732d747a48663467d21c4282fb6705f3916421912ec4312ccf3cc6258933e35040000004847304402206f0e939e09a0ccb4d746663e15091aaa5ea64699b8f2faa515c079f41a0f2b4c02204dc5d887f6fc70c6488c644e6adc7e749fd0cbb5195eb986704e486a8a31ec3101ffffffff611904eeb777c1f1c86262fa7f8e3191a2125ee4c8440837e5b8604144dcb526090000004847304402206ec15a69e81569b606b550a7af9530172923c6933a6832608d8fb8f8cf9067ba0220136f0aaa4790e9120da876fa2cfa963b96d2774026c0f803d0924a6cefbf3d0e01fffffffff0300247cd2234bcffd923895b579cf7fbcba5405df5f09c468da835cc416e9005000000484730440220119ee524eae3810da16132e1e9aeb28f23ad81780389808124897f4ebfbacee302205204643fbccbd8befb5d1b71dbcca4a44b6ef0b32fcc894b3fed76ccfc6bd7c601ffffffffa377c825ea5a03dc93c93a41ac06f58042512d5098333574d6de0d8a6d5b99820700000049483045022100ad752b6d0ab189bc1a267008816d8cac4982823dc20a60967a078dc9ed17348e022066c4779c21f706ee3c4aa0f956e0d2a746c2cfb587550c07c5a6a2385c1f3ebf01ffffffff02b0890700000000002321020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9ac00000000000000002a6a28071c4524afe8cf8e412b6fdb06e65795839f189205119294d26939c61c37880a084409004b4d440000000000";
     bool z = add_ntz_txn_to_extra(tx.extra, empty ? ntz : ntz_string_rem);
     if (!z) {
       MERROR("Failed to add ntz_tx data to extra!");
       return false;
     }*/

    struct input_generation_context_data
    {
      keypair in_ephemeral;
    };
    std::vector<input_generation_context_data> in_contexts;

    uint64_t summary_inputs_money = 0;
    //fill inputs
    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.outputs.size())
      {
        LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
        return false;
      }
      summary_inputs_money += src_entr.amount;

      //key_derivation recv_derivation;
      in_contexts.push_back(input_generation_context_data());
      keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      crypto::key_image img;
      const auto& out_key = reinterpret_cast<const crypto::public_key&>(src_entr.outputs[src_entr.real_output].second.dest);
      if(!generate_key_image_helper(sender_account_keys, subaddresses, out_key, src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys, src_entr.real_output_in_tx_index, in_ephemeral,img, hwdev))
      {
        LOG_ERROR("Key image generation failed!");
        return false;
      }

      //check that derivated key is equal with real output key (if non multisig)
      if(!msout && !(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< ENDL << "derived_key:"
          << string_tools::pod_to_hex(in_ephemeral.pub) << ENDL << "real output_public_key:"
          << string_tools::pod_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
        LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      //put key image into tx input
      txin_to_key input_to_key;
      input_to_key.amount = src_entr.amount;
      input_to_key.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;

      //fill outputs array and use relative offsets
      for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
        input_to_key.key_offsets.push_back(out_entry.first);

      input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
      tx.vin.push_back(input_to_key);
    }

    // "Shuffle" outs
    std::vector<tx_destination_entry> shuffled_dsts(destinations);
    std::random_shuffle(shuffled_dsts.begin(), shuffled_dsts.end(), [](unsigned int i) { return crypto::rand<unsigned int>() % i; });

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    if (num_stdaddresses == 0 && num_subaddresses == 1)
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(single_dest_subaddress.m_spend_public_key), rct::sk2rct(tx_key)));
    }
    else
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
    }
    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
    add_tx_pub_key_to_extra(tx, txkey_pub);

    std::vector<crypto::public_key> additional_tx_public_keys;
    // we don't need to include additional tx keys if:
    //   - all the destinations are standard addresses
    //   - there's only one destination which is a subaddress
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    bool additional_tx_keys_present = additional_tx_public_keys.size() > 0;
    if (need_additional_txkeys || (!need_additional_txkeys && additional_tx_keys_present))
      CHECK_AND_ASSERT_MES(destinations.size() == additional_tx_keys.size(), false, "Wrong amount of additional tx keys");

    uint64_t summary_outs_money = 0;
    //fill outputs
    size_t output_index = 0;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      crypto::key_derivation derivation;
      crypto::public_key out_eph_public_key;

      // make additional tx pubkey if necessary
      keypair additional_txkey;
      if (need_additional_txkeys || (!need_additional_txkeys && additional_tx_keys_present))
      {
        additional_txkey.sec = additional_tx_keys[output_index];
        if (dst_entr.is_subaddress)
          additional_txkey.pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(dst_entr.addr.m_spend_public_key), rct::sk2rct(additional_txkey.sec)));
        else
          additional_txkey.pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(additional_txkey.sec)));
      }

      bool r;
      if (change_addr && dst_entr.addr == *change_addr)
      {
        // sending change to yourself; derivation = a*R
        r = hwdev.generate_key_derivation(txkey_pub, sender_account_keys.m_view_secret_key, derivation);
        CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to generate_key_derivation(" << txkey_pub << ", " << sender_account_keys.m_view_secret_key << ")");
      }
      else
      {
        // sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
        r = hwdev.generate_key_derivation(dst_entr.addr.m_view_public_key, dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key, derivation);
        CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to generate_key_derivation(" << dst_entr.addr.m_view_public_key << ", " << (dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key) << ")");
      }

      if (need_additional_txkeys)
      {
        additional_tx_public_keys.push_back(additional_txkey.pub);
      }
      else if (additional_tx_keys_present)
      {
        additional_tx_public_keys.push_back(additional_txkey.pub);
      }

      if (tx.version >= 1)
      {
        crypto::secret_key scalar1;
        hwdev.derivation_to_scalar(derivation, output_index, scalar1);
        amount_keys.push_back(rct::sk2rct(scalar1));
      }
      r = hwdev.derive_public_key(derivation, output_index, dst_entr.addr.m_spend_public_key, out_eph_public_key);
      CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to derive_public_key(" << derivation << ", " << output_index << ", "<< dst_entr.addr.m_spend_public_key << ")");

      hwdev.add_output_key_mapping(dst_entr.addr.m_view_public_key, dst_entr.addr.m_spend_public_key, dst_entr.is_subaddress, output_index, amount_keys.back(), out_eph_public_key);

      tx_out out;
      out.amount = dst_entr.amount;
      txout_to_key tk;
      tk.key = out_eph_public_key;
      out.target = tk;
      tx.vout.push_back(out);
      output_index++;
      summary_outs_money += dst_entr.amount;
    }
    CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");

    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_additional_pub_keys));

    LOG_PRINT_L2("tx pubkey: " << txkey_pub);
    if (need_additional_txkeys || (!need_additional_txkeys && additional_tx_keys_present))
    {
      LOG_PRINT_L2("additional tx pubkeys: ");
      for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
        LOG_PRINT_L2(additional_tx_public_keys[i]);
      add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
    }

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return false;
    }

    // check for watch only wallet
    bool zero_secret_key = true;
    for (size_t i = 0; i < sizeof(sender_account_keys.m_spend_secret_key); ++i)
      zero_secret_key &= (sender_account_keys.m_spend_secret_key.data[i] == 0);
    if (zero_secret_key)
    {
      MDEBUG("Null secret key, skipping signatures");
    }

    if (tx.version >= 1)
    {
      size_t n_total_outs = sources[0].outputs.size(); // only for non-simple rct

      // the non-simple version is slightly smaller, but assumes all real inputs
      // are on the same index, so can only be used if there just one ring.
      bool use_simple_rct = sources.size() > 1;

      if (!use_simple_rct)
      {
        // non simple ringct requires all real inputs to be at the same index for all inputs
        for(const tx_source_entry& src_entr:  sources)
        {
          if(src_entr.real_output != sources.begin()->real_output)
          {
            LOG_ERROR("All inputs must have the same index for non-simple ringct");
            return false;
          }
        }

        // enforce same mixin for all outputs
        for (size_t i = 1; i < sources.size(); ++i) {
          if (n_total_outs != sources[i].outputs.size()) {
            LOG_ERROR("Non-simple ringct transaction has varying ring size");
            return false;
          }
        }
      }

      uint64_t amount_in = 0, amount_out = 0;
      rct::ctkeyV inSk;
      inSk.reserve(sources.size());
      // mixRing indexing is done the other way round for simple
      rct::ctkeyM mixRing(use_simple_rct ? sources.size() : n_total_outs);
      rct::keyV destinations;
      std::vector<uint64_t> inamounts, outamounts;
      std::vector<unsigned int> index;
      std::vector<rct::multisig_kLRki> kLRki;
      for (size_t i = 0; i < sources.size(); ++i)
      {
        rct::ctkey ctkey;
        amount_in += sources[i].amount;
        inamounts.push_back(sources[i].amount);
        index.push_back(sources[i].real_output);
        // inSk: (secret key, mask)
        ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
        ctkey.mask = sources[i].mask;
        inSk.push_back(ctkey);
        memwipe(&ctkey, sizeof(rct::ctkey));
        // inPk: (public key, commitment)
        // will be done when filling in mixRing
        if (msout)
        {
          kLRki.push_back(sources[i].multisig_kLRki);
        }
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        destinations.push_back(rct::pk2rct(boost::get<txout_to_key>(tx.vout[i].target).key));
        outamounts.push_back(tx.vout[i].amount);
        amount_out += tx.vout[i].amount;
      }

      if (use_simple_rct)
      {
        // mixRing indexing is done the other way round for simple
        for (size_t i = 0; i < sources.size(); ++i)
        {
          mixRing[i].resize(sources[i].outputs.size());
          for (size_t n = 0; n < sources[i].outputs.size(); ++n)
          {
            mixRing[i][n] = sources[i].outputs[n].second;
          }
        }
      }
      else
      {
        for (size_t i = 0; i < n_total_outs; ++i) // same index assumption
        {
          mixRing[i].resize(sources.size());
          for (size_t n = 0; n < sources.size(); ++n)
          {
            mixRing[i][n] = sources[n].outputs[i].second;
          }
        }
      }

      // fee
      if (!use_simple_rct && amount_in > amount_out)
        outamounts.push_back(amount_in - amount_out);

      // zero out all amounts to mask rct outputs, real amounts are now encrypted
      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (sources[i].rct)
          boost::get<txin_to_key>(tx.vin[i]).amount = 0;
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
        tx.vout[i].amount = 0;

      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash);
      rct::ctkeyV outSk;
      if (use_simple_rct)
        tx.rct_signatures = rct::genRctSimple(rct::hash2rct(tx_prefix_hash), inSk, destinations, inamounts, outamounts, amount_in - amount_out, mixRing, amount_keys, msout ? &kLRki : NULL, msout, index, outSk, bulletproof, hwdev);
      else
        tx.rct_signatures = rct::genRct(rct::hash2rct(tx_prefix_hash), inSk, destinations, outamounts, mixRing, amount_keys, msout ? &kLRki[0] : NULL, msout, sources[0].real_output, outSk, bulletproof, hwdev); // same index assumption
      memwipe(inSk.data(), inSk.size() * sizeof(rct::ctkey));

      CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);
    }

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, std::vector<uint8_t> extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, bool rct, bool bulletproof, rct::multisig_out *msout)
  {
    hw::device &hwdev = sender_account_keys.get_device();
    hwdev.open_tx(tx_key);

    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    bool additional_tx_keys_present = additional_tx_keys.size() > 0;
    if (need_additional_txkeys || (!need_additional_txkeys && additional_tx_keys_present))
    {
      additional_tx_keys.clear();
      for (const auto &d: destinations)
        additional_tx_keys.push_back(keypair::generate(sender_account_keys.get_device()).sec);
    }

    bool r = construct_tx_with_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct, bulletproof, msout);
    hwdev.close_tx();
    return r;
  }
  //---------------------------------------------------------------
  bool construct_ntz_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, std::vector<uint8_t> extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, bool rct, bool bulletproof, rct::multisig_out *msout)
  {
    hw::device &hwdev = sender_account_keys.get_device();
    hwdev.open_tx(tx_key);

    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
    int signer_index = -1;
    bool auth = auth_and_get_ntz_signer_index(destinations, change_addr, num_stdaddresses, sender_account_keys, signer_index);
    if (!auth) return false;
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    bool additional_tx_keys_present = additional_tx_keys.size() > 0;
    if (need_additional_txkeys || (!need_additional_txkeys && additional_tx_keys_present))
    {
      additional_tx_keys.clear();
      for (const auto &d: destinations)
        additional_tx_keys.push_back(keypair::generate(sender_account_keys.get_device()).sec);
    }

    bool r = construct_tx_with_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct, bulletproof, msout);
    hwdev.close_tx();
    return r;
  }
  //---------------------------------------------------------------
  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, std::vector<uint8_t> extra, transaction& tx, uint64_t unlock_time)
  {
     std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
     subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0,0};
     crypto::secret_key tx_key;
     std::vector<crypto::secret_key> additional_tx_keys;
   //  added below from Masari... but why are we making a copy?
     std::vector<tx_destination_entry> destinations_copy = destinations;
     return construct_tx_and_get_tx_key(sender_account_keys, subaddresses, sources, destinations_copy, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, false, false, NULL);
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(block& bl, network_type nettype)
  {
    //genesis block
    bl = boost::value_initialized<block>();

    blobdata tx_bl;
    bool r = string_tools::parse_hexstr_to_binbuff(nettype == cryptonote::MAINNET ? config::GENESIS_TX : config::testnet::GENESIS_TX, tx_bl);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    bl.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    bl.timestamp = 0;
    bl.nonce = config::GENESIS_NONCE;
    miner::find_nonce_for_given_block(bl, 1, 0);
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
}
