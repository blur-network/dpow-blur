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

#include "komodo_notaries.h"
#include "notary_server/notary_server.h"
#include "common/hex_str.h"
#include "bitcoin/bitcoin.h"
#include "libbtc/include/btc/wallet.h"

namespace cryptonote {

static char const* CRYPTO777_PUBSECPSTR[33] = { "020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9" };
static uint64_t const KOMODO_MINRATIFY = 11;
static uint64_t const  KOMODO_ELECTION_GAP = 2000;
static uint64_t const  KOMODO_ASSETCHAIN_MAXLEN = 64;
static uint64_t const  KOMODO_NOTARIES_TIMESTAMP1 = 1525132800; // May 1st 2018 1530921600 // 7/7/2017
static uint64_t const  KOMODO_NOTARIES_HEIGHT1 = ((814000 / KOMODO_ELECTION_GAP) * KOMODO_ELECTION_GAP);

  const char* Notaries_elected[64][3] =
  {
    {"tonyL_2",            "033ac7d60d65246a59524d8cb83e2f7be9209c763650547cbd882bb4d6ba7769e1", "4896933c13adc197b7d0cc571559247eccbd11ed3d470acdf2853106df5b5205" }, // 0
    {"alright_test",       "0235e22a9fb097965fb55b2b3f08a16fba4e55be042dfd00982dcf223471cd77b3", "662f177fbbba32bbd5abede145679d543ffecc7f76632ad480056f0b87f38eef" },
    {"strob_NA",           "0206f7a2e972d9dfef1c424c731503a0a27de1ba7a15a91a362dc7ec0d0fb47685", "60f2567a6b0a1ab57db5d55b581369b9dd05ee32f8a39f5b8cf213c22fb092e8" },
    {"dwy_EU",             "021c7cf1f10c4dc39d13451123707ab780a741feedab6ac449766affe37515a29e", "b70dff34c690235ecb33f961450afbfca429baf1a91e7ceee57881a50c4feba7" },
    {"phm87_SH",           "021773a38db1bc3ede7f28142f901a161c7b7737875edbb40082a201c55dcf0add", "b78a8dc587333a527a3c41d189d7ccdcff5854bbfb1333761bc3cffeb4a0b3cd" },
    {"chainmakers_NA",     "02285d813c30c0bf7eefdab1ff0a8ad08a07a0d26d8b95b3943ce814ac8e24d885", "6ad4d48ab844084b2207512b7c082ebb9cc363ae0747893a1aaab2041ecbf190" },
    {"indenodes_EU",       "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"blackjok3r_SH",      "021eac26dbad256cbb6f74d41b10763183ee07fb609dbd03480dd50634170547cc", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainmakers_EU",     "03fdf5a3fce8db7dee89724e706059c32e5aa3f233a6b6cc256fea337f05e3dbf7", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"biz_test",           "037db090cbbe154b7e0a0742032208250537e42ad822968cd5419ce5913a4d8afb", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"fullmoon_SH",        "023b7252968ea8a955cd63b9e57dee45a74f2d7ba23b4e0595572138ad1fb42d21", "31846bace49aaf4290e48c499e32f3bd8b57d46a9918d48232f4ea81aa529ab7" }, // 10
    {"indenodes_NA",       "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chmex_EU",           "0281304ebbcc39e4f09fda85f4232dd8dacd668e20e5fc11fba6b985186c90086e", "ed28f5f57c653d539fa0aa0bbe1270b53280049dc8bb4835a269eddcc140a2fd" },
    {"metaphilibert_SH",   "0284af1a5ef01503e6316a2ca4abf8423a794e9fc17ac6846f042b6f4adedc3309", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"ca333_DEV",          "02856843af2d9457b5b1c907068bef6077ea0904cc8bd4df1ced013f64bf267958", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"cipi_NA",            "02858904a2a1a0b44df4c937b65ee1f5b66186ab87a751858cf270dee1d5031f18", "dcaa0ce7328dfa4f354d34957b571348503b6aa13debcd5ce78fd84e798ac02c" },
    {"pungocloud_SH",      "024dfc76fa1f19b892be9d06e985d0c411e60dbbeb36bd100af9892a39555018f6", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"voskcoin_EU",        "034190b1c062a04124ad15b0fa56dfdf34aa06c164c7163b6aec0d654e5f118afb", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"decker_DEV",         "028eea44a09674dda00d88ffd199a09c9b75ba9782382cc8f1e97c0fd565fe5707", "2883dd7885a752fb55a89074e7b5d38b08c22a9e9b2b0da9bc74cad8fca83864" },
    {"cryptoeconomy_EU",   "0290ab4937e85246e048552df3e9a66cba2c1602db76e03763e16c671e750145d1", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"etszombi_EU",        "0293ea48d8841af7a419a24d9da11c34b39127ef041f847651bae6ab14dcd1f6b4", "f74b0f886d03d3b244fcd3f89644a75e8199ae110f30e150ae6856a223e51a42" },  // 20
    {"karasugoi_NA",       "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982", "e67ed3080f774a73d092e9fbd698feb84b361550b753e1af6e0304053fa2a639" },
    {"pirate_AR",          "03e29c90354815a750db8ea9cb3c1b9550911bb205f83d0355a061ac47c4cf2fde", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"metaphilibert_AR",   "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"zatjum_SH",          "02d6b0c89cacd58a0af038139a9a90c9e02cd1e33803a1f15fceabea1f7e9c263a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"madmax_AR",          "03c5941fe49d673c094bc8e9bb1a95766b4670c88be76d576e915daf2c30a454d3", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"lukechilds_NA",      "03f1051e62c2d280212481c62fe52aab0a5b23c95de5b8e9ad5f80d8af4277a64b", "964bf5389aa488a5848526c0bbbdcad30a8f53c140cc6b78a0f06a97259fca2b" },
    {"cipi_AR",            "02c4f89a5b382750836cb787880d30e23502265054e1c327a5bfce67116d757ce8", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"tonyl_AR",           "03a8db38075c80348889871b4318b0a79a1fd7e9e21daefb4ca6e4f05e5963569c", "d9bd811bf5d28fd2c0389fe322a9ef1bb8eb19ca4e4e3d693385f88de5ef2c1d" },
    {"infotech_DEV",       "0345ad4ab5254782479f6322c369cec77a7535d2f2162d103d666917d5e4f30c4c", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"fullmoon_NA",        "032c716701fe3a6a3f90a97b9d874a9d6eedb066419209eed7060b0cc6b710c60b", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },  // 30
    {"etszombi_AR",        "02e55e104aa94f70cde68165d7df3e162d4410c76afd4643b161dea044aa6d06ce", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"node-9_EU",          "0372e5b51e86e2392bb15039bac0c8f975b852b45028a5e43b324c294e9f12e411", "7a0f6733307fe41c52a98c487cdf0ba2634668649b990fb582de58102b3cb07b" },
    {"phba2061_EU",        "03f6bd15dba7e986f0c976ea19d8a9093cb7c989d499f1708a0386c5c5659e6c4e", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"indenodes_AR",       "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"and1-89_EU",         "02736cbf8d7b50835afd50a319f162dd4beffe65f2b1dc6b90e64b32c8e7849ddd", "1ad196fd9caf34c764e1a4a3cb6129feea72d6df94cc7b2b0719c60e434729b7" },
    {"komodopioneers_SH",  "032a238a5747777da7e819cfa3c859f3677a2daf14e4dce50916fc65d00ad9c52a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"komodopioneers_EU",  "036d02425916444fff8cc7203fcbfc155c956dda5ceb647505836bef59885b6866", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"d0ct0r_NA",          "0303725d8525b6f969122faf04152653eb4bf34e10de92182263321769c334bf58", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"kolo_DEV",           "02849e12199dcc27ba09c3902686d2ad0adcbfcee9d67520e9abbdda045ba83227", "2707b75bc3f70f9e9af6a7a2c4357564beabc33f2399862f7d2f486e76bfc960" },
    {"peer2cloud_AR",      "02acc001fe1fe8fd68685ba26c0bc245924cb592e10cec71e9917df98b0e9d7c37", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }, // 40
    {"webworker01_SH",     "031e50ba6de3c16f99d414bb89866e578d963a54bde7916c810608966fb5700776", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"webworker01_NA",     "032735e9cad1bb00eaababfa6d27864fa4c1db0300c85e01e52176be2ca6a243ce", "6770162f86036b460878bd75c139ae147e8ae50306017b5d13dfdf94558da7ff" },
    {"pbca26_NA",          "03a97606153d52338bcffd1bf19bb69ef8ce5a7cbdc2dbc3ff4f89d91ea6bbb4dc", "e5332b7470a8221e3daa448951266984d0b5ee9e3d633b5af979bfdefa1a7a78" },
    {"indenodes_SH",       "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pirate_NA",          "0255e32d8a56671dee8aa7f717debb00efa7f0086ee802de0692f2d67ee3ee06ee", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"lukechilds_AR",      "025c6a73ff6d750b9ddf6755b390948cffdd00f344a639472d398dd5c6b4735d23", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"dragonhound_NA",     "0224a9d951d3a06d8e941cc7362b788bb1237bb0d56cc313e797eb027f37c2d375", "0467e09834b304864f1a650add6eb806be7daf5aabde678b81cb1838cff40bd7" },
    {"fullmoon_AR",        "03da64dd7cd0db4c123c2f79d548a96095a5a103e5b9d956e9832865818ffa7872", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainzilla_SH",      "0360804b8817fd25ded6e9c0b50e3b0782ac666545b5416644198e18bc3903d9f9", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"titomane_EU",        "03772ac0aad6b0e9feec5e591bff5de6775d6132e888633e73d3ba896bdd8e0afb", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }, // 50
    {"jeezy_EU",           "037f182facbad35684a6e960699f5da4ba89e99f0d0d62a87e8400dd086c8e5dd7", "5a59e8d97daf7d4e1acd82a01e2253c1f577dd7c2d73d49741e53bac93373c06" },
    {"tonyL_DEV",          "03a8db38075c80348889871b4318b0a79a1fd7e9e21daefb4ca6e4f05e5963569c", "0cb1c911f0b3633087f567dc92de799735dea316c5e62c3461dfa007d09d2d91" },
    {"alien_AR",           "03911a60395801082194b6834244fa78a3c30ff3e888667498e157b4aa80b0a65f", "c1bbb2a4cc2bc83a8763768bc4b038d58ec805d533d2bbbc548a08bb367c25e4" },
    {"pirate_EU",          "03fff24efd5648870a23badf46e26510e96d9e79ce281b27cfe963993039dd1351", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"thegaltmines_NA",    "02db1a16c7043f45d6033ccfbd0a51c2d789b32db428902f98b9e155cf0d7910ed", "c10b72762e43b8112f38c5e12f4a039ad367b51fc95cc7b5d35c54b221c857c4" },
    {"computergenie_NA",   "03a78ae070a5e9e935112cf7ea8293f18950f1011694ea0260799e8762c8a6f0a4", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"nutellalicka_SH",    "02f7d90d0510c598ce45915e6372a9cd0ba72664cb65ce231f25d526fc3c5479fc", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainstrike_SH",     "03b806be3bf7a1f2f6290ec5c1ea7d3ea57774dcfcf2129a82b2569e585100e1cb", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"dwy_SH",             "036536d2d52d85f630b68b050f29ea1d7f90f3b42c10f8c5cdf3dbe1359af80aff", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"alien_EU",           "03bb749e337b9074465fa28e757b5aa92cb1f0fea1a39589bca91a602834d443cd", "e5b7b39fb50dcd63f5601a588768775a7b066c6cd80500027c741cc2fe90dc15" }, // 60
    {"gt_AR",              "0348430538a4944d3162bb4749d8c5ed51299c2434f3ee69c11a1f7815b3f46135", "f65f06bdb98b486db5795eab4526199619d50f90b27d9b42ed283ddaa6cdf886" },
    {"patchkez_SH",        "03f45e9beb5c4cd46525db8195eb05c1db84ae7ef3603566b3d775770eba3b96ee", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"decker_AR",          "03ffdf1a116300a78729608d9930742cd349f11a9d64fcc336b8f18592dd9c91bc", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }, // 63
  };

  bool get_notary_pubkeys(std::vector<std::pair<crypto::public_key,crypto::public_key>>& notary_pubkeys)
  {

    std::vector<std::pair<std::string,std::string>> notaries_keys;

    for (int i =0; i < 64; i++) {
        std::pair<const char*,const char*> seed_and_pubkey_pair;
        seed_and_pubkey_pair = std::make_pair(Notaries_elected[i][1], Notaries_elected[i][2]);
        //MWARNING("First: " << Notaries_elected[i][1] << ", Second: " << Notaries_elected[i][2]);
        notaries_keys.push_back(seed_and_pubkey_pair);
    }

    for (int n = 0; n < 64; n++)
    {
      std::string viewkey_seed_oversize = notaries_keys[n].first;
      std::string viewkey_seed_str = viewkey_seed_oversize.substr(2, 64);
//      MWARNING("viewkey_seed_str: " << viewkey_seed_str);
      cryptonote::blobdata btc_pubkey_data;

      if(!epee::string_tools::parse_hexstr_to_binbuff(viewkey_seed_str, btc_pubkey_data) || btc_pubkey_data.size() != sizeof(crypto::secret_key))
      {
        MERROR("Error: failed to parse btc_pubkey_data");
        return false;
      }

      const crypto::secret_key btc_pubkey_secret = *reinterpret_cast<const crypto::secret_key*>(btc_pubkey_data.data());
      crypto::public_key view_pubkey;
      crypto::secret_key view_seckey;
      crypto::secret_key rngview = crypto::generate_keys(view_pubkey, view_seckey, btc_pubkey_secret, true);

      std::string spendkey_pub_str = notaries_keys[n].second;
      cryptonote::blobdata spendkey_pub_data;


      if(!epee::string_tools::parse_hexstr_to_binbuff(spendkey_pub_str, spendkey_pub_data) || spendkey_pub_data.size() != sizeof(crypto::public_key))
      {
        MERROR("Error: failed to parse hardcoded spend public key");
        return false;
      }
      const crypto::public_key public_spend_key = *reinterpret_cast<const crypto::public_key*>(spendkey_pub_data.data());
      const crypto::public_key public_view_key = view_pubkey;
      std::pair<const crypto::public_key, const crypto::public_key> pair = std::make_pair(public_view_key,public_spend_key);
      notary_pubkeys.push_back(pair);
    }
    return true;
  }

  bool get_notary_secret_viewkeys(std::vector<crypto::secret_key>& notary_viewkeys)
  {

    std::vector<std::string> notary_seed_strings;

    for (int i =0; i < 64; i++) {
        const char* seed = Notaries_elected[i][1];
   //     MWARNING("First: " << Notaries_elected[i][1] << ", Second: " << Notaries_elected[i][3]);
        notary_seed_strings.push_back(seed);
    }

    for (int n = 0; n < 64; n++)
    {
      std::string viewkey_seed_oversize = notary_seed_strings[n];
      std::string viewkey_seed_str = viewkey_seed_oversize.substr(2, 64);
     // MWARNING("viewkey_seed_str: " << viewkey_seed_str);
      cryptonote::blobdata btc_pubkey_data;

      if(!epee::string_tools::parse_hexstr_to_binbuff(viewkey_seed_str, btc_pubkey_data) || btc_pubkey_data.size() != sizeof(crypto::secret_key))
      {
        MERROR("Error: failed to parse btc_pubkey_data");
        return false;
      }

      const crypto::secret_key btc_pubkey_secret = *reinterpret_cast<const crypto::secret_key*>(btc_pubkey_data.data());
      crypto::public_key view_pubkey;
      crypto::secret_key view_seckey;
      crypto::secret_key rngview = crypto::generate_keys(view_pubkey, view_seckey, btc_pubkey_secret, true);

      const crypto::secret_key vk = view_seckey;
      notary_viewkeys.push_back(vk);
    }
    return true;
   }

namespace komodo {

   std::string NOTARY_PUBKEY;
   uint8_t NOTARY_PUBKEY33[33];
   int32_t NUM_NPOINTS,last_NPOINTSi,NOTARIZED_HEIGHT,NOTARIZED_MOMDEPTH,KOMODO_NEEDPUBKEYS,NOTARIZED_PREVHEIGHT;
   uint256 NOTARIZED_HASH, NOTARIZED_MOM, NOTARIZED_DESTTXID;

// following is ported from libtom
/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#define GET_MIN(a,b) (((a)<(b)) ? (a) : (b))

#define STORE32L(x, y)                                                                     \
{ (y)[3] = (uint8_t)(((x)>>24)&255); (y)[2] = (uint8_t)(((x)>>16)&255);   \
(y)[1] = (uint8_t)(((x)>>8)&255); (y)[0] = (uint8_t)((x)&255); }

#define LOAD32L(x, y)                            \
{ x = (uint32_t)(((uint64_t)((y)[3] & 255)<<24) | \
((uint32_t)((y)[2] & 255)<<16) | \
((uint32_t)((y)[1] & 255)<<8)  | \
((uint32_t)((y)[0] & 255))); }

#define STORE64L(x, y)                                                                     \
{ (y)[7] = (uint8_t)(((x)>>56)&255); (y)[6] = (uint8_t)(((x)>>48)&255);   \
(y)[5] = (uint8_t)(((x)>>40)&255); (y)[4] = (uint8_t)(((x)>>32)&255);   \
(y)[3] = (uint8_t)(((x)>>24)&255); (y)[2] = (uint8_t)(((x)>>16)&255);   \
(y)[1] = (uint8_t)(((x)>>8)&255); (y)[0] = (uint8_t)((x)&255); }

#define LOAD64L(x, y)                                                       \
{ x = (((uint64_t)((y)[7] & 255))<<56)|(((uint64_t)((y)[6] & 255))<<48)| \
(((uint64_t)((y)[5] & 255))<<40)|(((uint64_t)((y)[4] & 255))<<32)| \
(((uint64_t)((y)[3] & 255))<<24)|(((uint64_t)((y)[2] & 255))<<16)| \
(((uint64_t)((y)[1] & 255))<<8)|(((uint64_t)((y)[0] & 255))); }

#define STORE32H(x, y)                                                                     \
{ (y)[0] = (uint8_t)(((x)>>24)&255); (y)[1] = (uint8_t)(((x)>>16)&255);   \
(y)[2] = (uint8_t)(((x)>>8)&255); (y)[3] = (uint8_t)((x)&255); }

#define LOAD32H(x, y)                            \
{ x = (uint32_t)(((uint64_t)((y)[0] & 255)<<24) | \
((uint32_t)((y)[1] & 255)<<16) | \
((uint32_t)((y)[2] & 255)<<8)  | \
((uint32_t)((y)[3] & 255))); }

#define STORE64H(x, y)                                                                     \
{ (y)[0] = (uint8_t)(((x)>>56)&255); (y)[1] = (uint8_t)(((x)>>48)&255);     \
(y)[2] = (uint8_t)(((x)>>40)&255); (y)[3] = (uint8_t)(((x)>>32)&255);     \
(y)[4] = (uint8_t)(((x)>>24)&255); (y)[5] = (uint8_t)(((x)>>16)&255);     \
(y)[6] = (uint8_t)(((x)>>8)&255); (y)[7] = (uint8_t)((x)&255); }

#define LOAD64H(x, y)                                                      \
{ x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
(((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
(((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
(((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); }

// Various logical functions
#define RORc(x, y) ( ((((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((y)&31)) | ((uint32_t)(x)<<(uint32_t)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

static inline int32_t sha256_vcompress(struct sha256_vstate * md,uint8_t *buf)
{
    uint32_t S[8],W[64],t0,t1,i;
    for (i=0; i<8; i++) // copy state into S
        S[i] = md->state[i];
    for (i=0; i<16; i++) // copy the state into 512-bits into W[0..15]
        LOAD32H(W[i],buf + (4*i));
    for (i=16; i<64; i++) // fill W[16..63]
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

#define RND(a,b,c,d,e,f,g,h,i,ki)                    \
t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
t1 = Sigma0(a) + Maj(a, b, c);                  \
d += t0;                                        \
h  = t0 + t1;

    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);
#undef RND
    for (i=0; i<8; i++) // feedback
        md->state[i] = md->state[i] + S[i];
    return(0);
}

#undef RORc
#undef Ch
#undef Maj
#undef S
#undef R
#undef Sigma0
#undef Sigma1
#undef Gamma0
#undef Gamma1

static inline void sha256_vinit(struct sha256_vstate * md)
{
    md->curlen = 0;
    md->length = 0;
    md->state[0] = 0x6A09E667UL;
    md->state[1] = 0xBB67AE85UL;
    md->state[2] = 0x3C6EF372UL;
    md->state[3] = 0xA54FF53AUL;
    md->state[4] = 0x510E527FUL;
    md->state[5] = 0x9B05688CUL;
    md->state[6] = 0x1F83D9ABUL;
    md->state[7] = 0x5BE0CD19UL;
}

static inline int32_t sha256_vprocess(struct sha256_vstate *md,const uint8_t *in,uint64_t inlen)
{
    uint64_t n; int32_t err;
    if ( md->curlen > sizeof(md->buf) )
        return(-1);
    while ( inlen > 0 )
    {
        if ( md->curlen == 0 && inlen >= 64 )
        {
            if ( (err= sha256_vcompress(md,(uint8_t *)in)) != 0 )
                return(err);
            md->length += 64 * 8, in += 64, inlen -= 64;
        }
        else
        {
            n = GET_MIN(inlen,64 - md->curlen);
            memcpy(md->buf + md->curlen,in,(size_t)n);
            md->curlen += n, in += n, inlen -= n;
            if ( md->curlen == 64 )
            {
                if ( (err= sha256_vcompress(md,md->buf)) != 0 )
                    return(err);
                md->length += 8*64;
                md->curlen = 0;
            }
        }
    }
    return(0);
}

static inline int32_t sha256_vdone(struct sha256_vstate *md,uint8_t *out)
{
    int32_t i;
    if ( md->curlen >= sizeof(md->buf) )
        return(-1);
    md->length += md->curlen * 8; // increase the length of the message
    md->buf[md->curlen++] = (uint8_t)0x80; // append the '1' bit
    // if len > 56 bytes we append zeros then compress.  Then we can fall back to padding zeros and length encoding like normal.
    if ( md->curlen > 56 )
    {
        while ( md->curlen < 64 )
            md->buf[md->curlen++] = (uint8_t)0;
        sha256_vcompress(md,md->buf);
        md->curlen = 0;
    }
    while ( md->curlen < 56 ) // pad upto 56 bytes of zeroes
        md->buf[md->curlen++] = (uint8_t)0;
    STORE64H(md->length,md->buf+56); // store length
    sha256_vcompress(md,md->buf);
    for (i=0; i<8; i++) // copy output
        STORE32H(md->state[i],out+(4*i));
    return(0);
}
// end libtom

  //------------------------------------------------------------------
  struct notarized_checkpoint
  {
    uint256 notarized_hash,notarized_desttxid,MoM,MoMoM;
    int32_t nHeight,notarized_height,MoMdepth,MoMoMdepth,MoMoMoffset,kmdstarti,kmdendi;
  } *NPOINTS;

  struct notarized_checkpoint *komodo_npptr(uint64_t height)
  {
    int i; struct notarized_checkpoint *np = 0;
    uint64_t notar_height = 0;
    if (np->notarized_height >= 0)
    {
      notar_height = np->notarized_height;
    }
    for (i=NUM_NPOINTS-1; i>=0; i--)
    {
        np = &NPOINTS[i];
        if ( /*np->MoMdepth > 0 &&  height > np->notarized_height-np->MoMdepth &&*/ height <= notar_height )
          return(np);
    }
    return(0);
  }

  void komodo_clearstate()
  {
   // portable_mutex_lock(&komodo_mutex);
    memset(&NOTARIZED_HEIGHT,0,sizeof(NOTARIZED_HEIGHT));
    std::fill(NOTARIZED_HASH.begin(),NOTARIZED_HASH.begin()+32,0);
    std::fill(NOTARIZED_DESTTXID.begin(),NOTARIZED_DESTTXID.begin()+32,0);
    std::fill(NOTARIZED_MOM.begin(),NOTARIZED_MOM.begin()+32,0);
    memset(&NOTARIZED_MOMDEPTH,0,sizeof(NOTARIZED_MOMDEPTH));
    memset(&last_NPOINTSi,0,sizeof(last_NPOINTSi));
  //  portable_mutex_unlock(&komodo_mutex);
  }

  komodo_core::komodo_core(cryptonote::core& cr, nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>& p2p) : m_core(cr), m_p2p(p2p) {};

  //------------------------------------------------------------------
  bool komodo_core::check_core_ready()
  {
    if(!m_p2p.get_payload_object().is_synchronized())
    {
    return false;
    }
    return true;
  }
  #define CHECK_CORE_READY() do { if(!check_core_ready()){res.status =  CORE_RPC_STATUS_BUSY;return true;} } while(0)

  int32_t komodo_core::komodo_chainactive_timestamp()
  {
     cryptonote::block b;
    if ( m_core.get_current_blockchain_height() != 0 ) {
        cryptonote::block b = m_core.get_blockchain_storage().get_db().get_top_block();
        return(b.timestamp);
    }
    return(0);
  }
  //------------------------------------------------------------------
  int32_t komodo_core::komodo_init(BlockchainDB* db)
  {
    return(0);
  }
  //------------------------------------------------------------------
  komodo_core* m_komodo_core;
  //------------------------------------------------------------------
  komodo_core& get_k_core()
  {
    return *m_komodo_core;
  }
  //------------------------------------------------------------------
  void komodo_core::komodo_disconnect(uint64_t height,cryptonote::block block)
  {
    uint64_t notarized_height = 0;
    if (NOTARIZED_HEIGHT >= 0)
    {
      notarized_height = NOTARIZED_HEIGHT;
    }
    if ( height <= notarized_height )
    {
  //      uint64_t block_height = m_core.get_blockchain_storage().get_db().get_block_id_by_height(block);
        uint64_t block_height = height;
        fprintf(stderr,"komodo_disconnect unexpected reorg at height = %lu vs NOTARIZED_HEIGHT = %d\n",block_height,NOTARIZED_HEIGHT);
        komodo_clearstate(); // bruteforce shortcut. on any reorg, no active notarization until next one is seen
    }
  }
  //------------------------------------------------------------------
  int32_t komodo_core::komodo_notarizeddata(uint64_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp)
  {
    struct notarized_checkpoint *np = 0; int32_t i=0,flag = 0;
    uint64_t notar_height = 0;
    if ( NUM_NPOINTS > 0 )
    {
        flag = 0;
        if ( last_NPOINTSi < NUM_NPOINTS && last_NPOINTSi > 0 )
        {
          np = &NPOINTS[last_NPOINTSi-1];
         if (np->notarized_height >= 0)
         {
           notar_height = np->notarized_height;
         }
          if ( notar_height < nHeight )
          {
            for (i=last_NPOINTSi; i<NUM_NPOINTS; i++)
            {
                if ( NPOINTS[i].nHeight >= 0 )
                {
                  notar_height = NPOINTS[i].nHeight;
                }
                if ( notar_height >= nHeight )
                {
                  printf("flag.1 i.%d np->ht %d [%d].ht %d >= nHeight.%lu, last.%d num.%d\n",i,np->nHeight,i,NPOINTS[i].nHeight,nHeight,last_NPOINTSi,NUM_NPOINTS);
                  flag = 1;
                  break;
                }
                np = &NPOINTS[i];
                last_NPOINTSi = i;
            }
          }
        }
        if ( flag == 0 )
        {
          np = 0;
          for (i=0; i<NUM_NPOINTS; i++)
          {
            uint64_t temp = 0;
            if (NPOINTS[i].nHeight >= 0)
            {
              temp = NPOINTS[i].nHeight;
            }
            if ( temp >= nHeight )
            {
                //printf("i.%d np->ht %d [%d].ht %d >= nHeight.%d\n",i,np->nHeight,i,NPOINTS[i].nHeight,nHeight);
                break;
            }
            np = &NPOINTS[i];
            last_NPOINTSi = i;
          }
        }
    }
    if ( np != 0 )
    {
      uint64_t n1_height = 0;
      if (np->nHeight >= 0)
      {
        notar_height = np->nHeight;
      }
      if (np[1].nHeight >= 0)
      {
        n1_height = np[1].nHeight;
      }
      if ( notar_height >= nHeight || (i < NUM_NPOINTS && n1_height < nHeight) )
        fprintf(stderr,"warning: flag.%d i.%d np->ht %d [1].ht %d >= nHeight.%lu\n",flag,i,np->nHeight,np[1].nHeight,nHeight);
      *notarized_hashp = np->notarized_hash;
      *notarized_desttxidp = np->notarized_desttxid;
      return(np->notarized_height);
    }
    std::fill(notarized_hashp->begin(),notarized_hashp->begin()+32,0);
    std::fill(notarized_desttxidp->begin(),notarized_desttxidp->begin()+32,0);
    return(0);
  }

  void komodo_core::komodo_update(cryptonote::core& m_core)
  {
    m_core.get_blockchain_storage().komodo_update();
  }

  //------------------------------------------------------------------
/*  void komodo_core::komodo_notarized_update(uint64_t nHeight,uint64_t notarized_height,uint256 notarized_hash,uint256 notarized_desttxid,uint256 MoM,int32_t MoMdepth)
  {
    static int didinit; static uint256 zero; static FILE *fp; cryptonote::block *pindex = nullptr; struct notarized_checkpoint *np,N; long fpos;
    if ( didinit == 0 )
    {
        char fname[512]; uint64_t latestht = 0;
//        decode_hex(NOTARY_PUBKEY33,33,(char *)NOTARY_PUBKEY.c_str());
        pthread_mutex_init(&komodo_mutex,NULL);
  //#ifdef _WIN32
  //      sprintf(fname,"%s\\notarizations",GetDefaultDataDir().string().c_str());
  //#else
  //      sprintf(fname,"%s/notarizations",GetDefaultDataDir().string().c_str());
  //#endif
  //     printf("fname.(%s)\n",fname);
        if ( (fp= fopen(fname,"rb+")) == 0 )
          fp = fopen(fname,"wb+");
        else
        {
          fpos = 0;
          while ( fread(&N,1,sizeof(N),fp) == sizeof(N) )
          {
            uint64_t n_height = 0;
            if (N.notarized_height >= 0)
            {
              n_height = N.notarized_height;
            }
            //pindex = komodo_chainactive(N.notarized_height);
            //if ( pindex != 0 && pindex->GetBlockHash() == N.notarized_hash && N.notarized_height > latestht )
            if ( n_height > latestht )
            {
                NPOINTS = (struct notarized_checkpoint *)realloc(NPOINTS,(NUM_NPOINTS+1) * sizeof(*NPOINTS));
                np = &NPOINTS[NUM_NPOINTS++];
                *np = N;
                latestht = np->notarized_height;
                NOTARIZED_HEIGHT = np->notarized_height;
                NOTARIZED_HASH = np->notarized_hash;
                NOTARIZED_DESTTXID = np->notarized_desttxid;
                NOTARIZED_MOM = np->MoM;
                NOTARIZED_MOMDEPTH = np->MoMdepth;
                fprintf(stderr,"%d ",np->notarized_height);
                fpos = ftell(fp);
            } //else fprintf(stderr,"%s error with notarization ht.%d %s\n",ASSETCHAINS_SYMBOL,N.notarized_height,pindex->GetBlockHash().ToString().c_str());
          }
          if ( ftell(fp) !=  fpos )
            fseek(fp,fpos,SEEK_SET);
        }
        printf("dpow: finished loading %s [%s]\n",fname,NOTARY_PUBKEY.c_str());
        didinit = 1;
    }
    if ( notarized_height == 0 )
        return;
    if ( notarized_height >= nHeight )
    {
        fprintf(stderr,"komodo_notarized_update REJECT notarized_height %lu > %lu nHeight\n",notarized_height,nHeight);
        return;
    }
    bool active = komodo_chainactive(notarized_height, *pindex);
  //    crypto::hash db_hash = m_core.get_block_hash_from_height(m_core.height());
  //    uint256 hash;
  //    std::vector<unsigned char> db_v = hex_to_bytes256(epee::string_tools::pod_to_hex(db_hash));
    if ( (!active) || notarized_height >= (m_core.get_blockchain_storage().get_db().height()-1) )
    {
  //      crypto::hash index_hash = m_core.get_blockchain_storage().get_db().get_block_hash(pindex);
        uint64_t index_height = cryptonote::get_block_height(*pindex);
        fprintf(stderr,"komodo_notarized_update reject nHeight.%lu notarized_height.%lu:%lu\n",nHeight,notarized_height, index_height);
        return;
    }
    fprintf(stderr,"komodo_notarized_update nHeight.%lu notarized_height.%lu prev.%d\n",nHeight,notarized_height,NPOINTS!=0?NPOINTS[NUM_NPOINTS-1].notarized_height:-1);
    portable_mutex_lock(&komodo_mutex);
    NPOINTS = (struct notarized_checkpoint *)realloc(NPOINTS,(NUM_NPOINTS+1) * sizeof(*NPOINTS));
    np = &NPOINTS[NUM_NPOINTS++];
    std::fill(np->notarized_hash.begin(),np->notarized_hash.begin()+32,0);
    std::fill(np->notarized_desttxid.begin(),np->notarized_desttxid.begin()+32,0);
    std::fill(np->MoM.begin(),np->MoM.begin()+32,0);

    np->nHeight = nHeight;
    NOTARIZED_HEIGHT = np->notarized_height = notarized_height;
    NOTARIZED_HASH = np->notarized_hash = notarized_hash;
    NOTARIZED_DESTTXID = np->notarized_desttxid = notarized_desttxid;
    if ( MoM != zero && MoMdepth > 0 )
    {
        NOTARIZED_MOM = np->MoM = MoM;
        NOTARIZED_MOMDEPTH = np->MoMdepth = MoMdepth;
    }
    if ( fp != 0 )
    {
        if ( fwrite(np,1,sizeof(*np),fp) == sizeof(*np) )
          fflush(fp);
        else printf("error writing notarization to %d\n",(int32_t)ftell(fp));
    }
    // add to stored notarizations
    portable_mutex_unlock(&komodo_mutex);
  }
  //------------------------------------------------------------------
  int32_t komodo_core::komodo_checkpoint(int32_t *notarized_heightp, uint64_t nHeight, crypto::hash& hash)
  {

    int32_t notarized_height; std::vector<uint8_t> zero;uint256 notarized_hash,notarized_desttxid; uint64_t notary; cryptonote::block *pindex = nullptr;
    //komodo_notarized_update(0,0,zero,zero,zero,0);
    uint64_t activeheight = m_core.get_blockchain_storage().get_db().height();
    bool active = komodo_chainactive(activeheight, *pindex);
    std::vector<uint8_t> v_nhash(notarized_hash.begin(), notarized_hash.begin()+32);
    std::string s_notarized_hash = bytes256_to_hex(v_nhash);
    if (!active)
        return(-1);
    notarized_height = komodo_notarizeddata(m_core.get_blockchain_storage().get_db().height(),&notarized_hash,&notarized_desttxid);
    *notarized_heightp = notarized_height;
    uint64_t temp_height = 0;
    if (notarized_height >= 0)
    {
      temp_height = notarized_height;
    }
    if ( notarized_height >= 0 && temp_height <= activeheight && (notary= m_core.get_blockchain_storage().get_db().get_block_height(hash) != 0 ))
    {
        LOG_PRINT_L2("activeheight = " << std::to_string(activeheight) << ", notarized_height = " << std::to_string(notarized_height) << ", notarized_hash = " << s_notarized_hash);
        if ( notary == temp_height ) // if notarized_hash not in chain, reorg
        {
          if ( activeheight < temp_height )
          {
            MERROR("activeheight = " << std::to_string(activeheight) << " less than " << std::to_string(NOTARIZED_HEIGHT));
            return(-1);
          }
          else if ( activeheight == temp_height && memcmp(&hash,&notarized_hash,sizeof(hash)) != 0 )
          {
            MERROR("nHeight == NOTARIZED_HEIGHT, but different hash!");
             Could probably use slightly more informative logging here
            return(-1);
          }
        } else {
           MERROR("Unexpected error notary_hash! " << s_notarized_hash << ", notarized_height = " << std::to_string(notarized_height) << ", notary = " << std::to_string(notary));
        }
    } else if ( notarized_height > 0 )
        MERROR("BLUR couldnt find notarized. " << ASSETCHAINS_SYMBOL << ", " << s_notarized_hash << ", notarized_height = " << std::to_string(notarized_height));
    return(0);
  }
  //------------------------------------------------------------------
  void komodo_core::komodo_connectblock(uint64_t& height,cryptonote::block& b)
  {
    static uint64_t hwmheight;
    uint64_t signedmask; uint8_t scriptbuf[4096],pubkeys[64][33],scriptPubKey[35]; crypto::hash zero; int i,j,k,numnotaries,notarized,scriptlen,numvalid,specialtx,notarizedheight,len,numvouts,numvins;
    size_t txn_count = 0;

    uint64_t nHeight = height;

    if ( KOMODO_NEEDPUBKEYS != 0 )
    {
        komodo_importpubkeys();
        KOMODO_NEEDPUBKEYS = 0;
    }
    memset(&zero,0,sizeof(zero));
    komodo_notarized_update(0,0,zero,zero,zero,0);
    numnotaries = komodo_notaries(pubkeys, nHeight, b.timestamp);

    if ( nHeight > hwmheight )
        hwmheight = nHeight;
    else
    {
        if ( nHeight != hwmheight )
          printf("dpow: %s hwmheight.%lu vs pindex->nHeight.%lu t.%lu reorg.%lu\n",ASSETCHAINS_SYMBOL,hwmheight,nHeight,b.timestamp,hwmheight - nHeight);
    }

    if ( height != 0 )
    {
        height = nHeight;
        std::vector<cryptonote::transaction> txs = b.tx_hashes;
        size_t txn_counter = 1;
        for (const auto& tx : txs) {
        ++txn_counter;
        }
        txn_count = tx_counter;
        //fprintf(stderr, "txn_count=%d\n", txn_count);
        for (i=0; i<txn_count; i++)
        {
          txhash = block.vtx[i]->GetHash();
          numvouts = b.vtx[i].vout.size();
          specialtx = notarizedheight = notarized = 0;
          signedmask = 0;
          numvins = block.vtx[i].vin.size();
      //fprintf(stderr, "tx=%d, numvouts=%d, numvins=%d\n", i, numvouts, numvins );
          for (j=0; j<numvins; j++)
          {
            if ( i == 0 && j == 0 )
                continue;
            if ( block.vtx[i].vin[j].prevout.hash != zero && (scriptlen= gettxout_scriptPubKey(height,scriptPubKey,sizeof(scriptPubKey),block.vtx[i].vin[j].prevout.hash,block.vtx[i].vin[j].prevout.n)) == 35 )
            {
                for (k=0; k<numnotaries; k++)
                  if ( memcmp(&scriptPubKey[1],pubkeys[k],33) == 0 )
                  {
                    signedmask |= (1LL << k);
                    break;
                  }
            }//   else if ( block.vtx[i].vin[j].prevout.hash != zero ) printf("%s cant get scriptPubKey for ht.%d txi.%d vin.%d\n",ASSETCHAINS_SYMBOL,height,i,j);
          }
          numvalid = bitweight(signedmask);
          if ( numvalid >= KOMODO_MINRATIFY )
            notarized = 1;
          if ( NOTARY_PUBKEY33[0] != 0 )
            printf("(tx.%d: ",i);
          for (j=0; j<numvouts; j++)
          {
            if ( NOTARY_PUBKEY33[0] != 0 )
                printf("%.8f ",dstr(block.vtx[i].vout[j].nValue));
            len = block.vtx[i].vout[j].scriptPubKey.size();
            if ( len >= (int32_t)sizeof(uint32_t) && len <= (int32_t)sizeof(scriptbuf) )
            {
                memcpy(scriptbuf,block.vtx[i].vout[j].scriptPubKey.data(),len);
                komodo_voutupdate(i,j,scriptbuf,len,height,&specialtx,&notarizedheight,(uint64_t)block.vtx[i].vout[j].nValue,notarized,signedmask);
            }
          }
          if ( NOTARY_PUBKEY33[0] != 0 )
            printf(") ");
          if ( NOTARY_PUBKEY33[0] != 0 )
            printf("%s ht.%d\n",ASSETCHAINS_SYMBOL,height);
          LogPrintf("dpow: [%s] ht.%d txi.%d signedmask.%llx numvins.%d numvouts.%d notarized.%d special.%d\n",ASSETCHAINS_SYMBOL,height,i,(long long)signedmask,numvins,numvouts,notarized,specialtx);
        }
    } else fprintf(stderr,"komodo_connectblock: unexpected null pindex\n");

    }*/
 //----------------------------------------------------------------------------
  int32_t komodo_init(BlockchainDB* db)
  {
    if (db == nullptr)
    {
      return (-1);
    }
    komodo_core& k_core = get_k_core();
    return k_core.komodo_init(db);
  }
  //------------------------------------------------------------------
  void komodo_core::vcalc_sha256(uint8_t hash[256 >> 3],uint8_t *src,int32_t len)
  {
    struct sha256_vstate md;
    sha256_vinit(&md);
    sha256_vprocess(&md,src,len);
    sha256_vdone(&md,hash);
  }
  //------------------------------------------------------------------
  void komodo_core::vcalc_sha256(uint8_t hash[256 >> 3],uint8_t const* src,int32_t len)
  {
    struct sha256_vstate md;
    sha256_vinit(&md);
    sha256_vprocess(&md,src,len);
    sha256_vdone(&md,hash);
  }
  //------------------------------------------------------------------
  bits256 komodo_core::bits256_doublesha256(uint8_t *data,int32_t datalen)
  {
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(hash.bytes,data,datalen);
    vcalc_sha256(hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<(int32_t)sizeof(hash); i++)
      hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    return(hash);
  }
  //------------------------------------------------------------------
  bits256 komodo_core::bits256_doublesha256(uint8_t const* data,int32_t datalen)
  {
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(hash.bytes,data,datalen);
    vcalc_sha256(hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<(int32_t)sizeof(hash); i++)
      hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    return(hash);
  }

} // namespace komodo
} // namespace cryptonote
