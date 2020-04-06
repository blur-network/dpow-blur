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
    {"madmax_NA",         "02ef81a360411adf71184ff04d0c5793fc41fd1d7155a28dd909f21f35f4883ac1", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"alright_AR",        "036a6bca1c2a8166f79fa8a979662892742346cc972b432f8e61950a358d705517", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"strob_NA",          "02049202f3872877e81035549f6f3a0f868d0ad1c9b0e0d2b48b1f30324255d26d", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"hunter_EU",         "0378224b4e9d8a0083ce36f2963ec0a4e231ec06b0c780de108e37f41181a89f6a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"phm87_SH",          "03889a10f9df2caef57220628515693cf25316fe1b0693b0241419e75d0d0e66ed", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainmakers_NA",    "030e4822bddba10eb50d52d7da13106486651e4436962078ee8d681bc13f4993e9", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"indenodes_EU",      "03a416533cace0814455a1bb1cd7861ce825a543c6f6284a432c4c8d8875b7ace9", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"blackjok3r_SH",     "03d23bb5aad3c20414078472220cc5c26bc5aeb41e43d72c99158d450f714d743a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainmakers_EU",    "034f8c0a504856fb3d80a94c3aa78828c1152daf8ccc45a17c450f32a1e242bb0c", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"titomane_AR",       "0358cd6d7460654a0ddd5125dd6fa0402d0719999444c6cc3888689a0b4446136a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"fullmoon_SH",       "0275031fa79846c5d667b1f7c4219c487d439cd367dd294f73b5ecd55b4e673254", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"indenodes_NA",      "02b3908eda4078f0e9b6704451cdc24d418e899c0f515fab338d7494da6f0a647b", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chmex_EU",          "03e5b7ab96b7271ecd585d6f22807fa87da374210a843ec3a90134cbf4a62c3db1", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"metaphilibert_SH",  "03b21ff042bf1730b28bde43f44c064578b41996117ac7634b567c3773089e3be3", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"ca333_DEV",         "029c0342ce2a4f9146c7d1ee012b26f5c2df78b507fb4461bf48df71b4e3031b56", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"cipi_NA",           "034406ac4cf94e84561c5d3f25384dd59145e92fefc5972a037dc6a44bfa286688", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pungocloud_SH",     "0203064e291045187927cc35ed350e046bba604e324bb0e3b214ea83c74c4713b1", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"voskcoin_EU",       "037bfd946f1dd3736ddd2cb1a0731f8b83de51be5d1be417496fbc419e203bc1fe", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"decker_DEV",        "02fca8ee50e49f480de275745618db7b0b3680b0bdcce7dcae7d2e0fd5c3345744", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"cryptoeconomy_EU",  "037d04b7d16de61a44a3fc766bea4b7791023a36675d6cee862fe53defd04dd8f2", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"etszombi_EU",       "02f65da26061d1b9f1756a274918a37e83086dbfe9a43d2f0b35b9d2f593b31907", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"karasugoi_NA",      "024ba10f7f5325fd6ec6cab50c5242d142d00fab3537c0002097c0e98f72014177", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pirate_AR",         "0353e2747f89968741c24f254caec24f9f49a894a0039ee9ba09234fcbad75c77d", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"metaphilibert_AR",  "0239e34ad22957bbf4c8df824401f237b2afe8d40f7a645ecd43e8f27dde1ab0da", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"zatjum_SH",         "03643c3b0a07a34f6ae7b048832e0216b935408dfc48b0c7d3d4faceb38841f3f3", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"madmax_AR",         "038735b4f6881925e5a9b14275af80fa2b712c8bd57eef26b97e5b153218890e38", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"lukechilds_NA",     "024607d85ea648511fa50b13f29d16beb2c3a248c586b449707d7be50a6060cf50", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"cipi_AR",           "025b7655826f5fd3a807cbb4918ef9f02fe64661153ca170db981e9b0861f8c5ad", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"tonyl_AR",          "03a8db38075c80348889871b4318b0a79a1fd7e9e21daefb4ca6e4f05e5963569c", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"infotech_DEV",      "0399ff59b0244103486a94acf1e4a928235cb002b20e26a6f3163b4a0d5e62db91", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"fullmoon_NA",       "02adf6e3cb8a3c94d769102aec9faf2cb073b7f2979ce64efb1161a596a8d16312", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"etszombi_AR",       "03c786702b81e0122157739c8e2377cf945998d36c0d187ec5c5ff95855848dfdd", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"node-9_EU",         "024f2402daddee0c8169ccd643e5536c2cf95b9690391c370a65c9dd0169fc3dc6", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"phba2061_EU",       "02dc98f064e3bf26a251a269893b280323c83f1a4d4e6ccd5e84986cc3244cb7c9", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"indenodes_AR",      "0242778789986d614f75bcf629081651b851a12ab1cc10c73995b27b90febb75a2", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"and1-89_EU",        "029f5a4c6046de880cc95eb448d20c80918339daff7d71b73dd3921895559d7ca3", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"komodopioneers_SH", "02ae196a1e93444b9fcac2b0ccee428a4d9232a00b3a508484b5bccaedc9bac55e", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"komodopioneers_EU", "03c7fef345ca6b5326de9d5a38498638801eee81bfea4ca8ffc3dacac43c27b14d", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"d0ct0r_NA",         "0235b211469d7c1881d30ab647e0d6ddb4daf9466f60e85e6a33a92e39dedde3a7", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"kolo_DEV",          "03dc7c71a5ef7104f81e62928446c4216d6e9f68d944c893a21d7a0eba74b1cb7c", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"peer2cloud_AR",     "0351c784d966dbb79e1bab4fad7c096c1637c98304854dcdb7d5b5aeceb94919b4", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"webworker01_SH",    "0221365d89a6f6373b15daa4a50d56d34ad1b4b8a48a7fd090163b6b5a5ecd7a0a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"webworker01_NA",    "03bfc36a60194b495c075b89995f307bec68c1bcbe381b6b29db47af23494430f9", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pbca26_NA",         "038319dcf74916486dbd506ac866d184c17c3202105df68c8335a1a1079ef0dfcc", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"indenodes_SH",      "031d1584cf0eb4a2d314465e49e2677226b1615c3718013b8d6b4854c15676a58c", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pirate_NA",         "034899e6e884b3cb1f491d296673ab22a6590d9f62020bea83d721f5c68b9d7aa7", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"lukechilds_AR",     "031ee242e67a8166e489c0c4ed1e5f7fa32dff19b4c1749de35f8da18befa20811", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"dragonhound_NA",    "022405dbc2ea320131e9f0c4115442c797bf0f2677860d46679ac4522300ce8c0a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"fullmoon_AR",       "03cd152ae20adcc389e77acad25953fc2371961631b35dc92cf5c96c7729c2e8d9", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainzilla_SH",     "03fe36ff13cb224217898682ce8b87ba6e3cdd4a98941bb7060c04508b57a6b014", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"titomane_EU",       "03d691cd0914a711f651082e2b7b27bee778c1309a38840e40a6cf650682d17bb5", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"jeezy_EU",          "022bca828b572cb2b3daff713ed2eb0bbc7378df20f799191eebecf3ef319509cd", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"titomane_SH",       "038c2a64f7647633c0e74eec93f9a668d4bf80214a43ed7cd08e4e30d3f2f7acfb", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"alien_AR",          "024f20c096b085308e21893383f44b4faf1cdedea9ad53cc7d7e7fbfa0c30c1e71", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pirate_EU",         "0371f348b4ac848cdfb732758f59b9fdd64285e7adf769198771e8e203638db7e6", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"thegaltmines_NA",   "03e1d4cec2be4c11e368ff0c11e80cd1b09da8026db971b643daee100056b110fa", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"computergenie_NA",  "02f945d87b7cd6e9f2173a110399d36b369edb1f10bdf5a4ba6fd4923e2986e137", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"nutellalicka_SH",   "035ec5b9e88734e5bd0f3bd6533e52f917d51a0e31f83b2297aabb75f9798d01ef", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainstrike_SH",    "0221f9dee04b7da1f3833c6ea7f7325652c951b1c239052b0dadb57209084ca6a8", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"hunter_SH",         "02407db70ad30ce4dfaee8b4ae35fae88390cad2b0ba0373fdd6231967537ccfdf", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"alien_EU",          "022b85908191788f409506ebcf96a892f3274f352864c3ed566c5a16de63953236", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"gt_AR",             "0307c1cf89bd8ed4db1b09a0a98cf5f746fc77df3803ecc8611cf9455ec0ce6960", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"patchkez_SH",       "03d7c187689bf829ca076a30bbf36d2e67bb74e16a3290d8a55df21d6cb15c80c1", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"decker_AR",         "02a85540db8d41c7e60bf0d33d1364b4151cad883dd032878ea4c037f67b769635", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }

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
   int32_t NUM_NPOINTS,last_NPOINTSi,NOTARIZED_HEIGHT,NOTARIZED_MOMDEPTH,KOMODO_NEEDPUBKEYS;
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

  void vcalc_sha256(uint8_t hash[256 >> 3],uint8_t *src,int32_t len)
  {
    struct sha256_vstate md;
    sha256_vinit(&md);
    sha256_vprocess(&md,src,len);
    sha256_vdone(&md,hash);
  }
  //------------------------------------------------------------------
  bits256 bits256_doublesha256(uint8_t *data,int32_t datalen)
  {
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(hash.bytes,data,datalen);
    vcalc_sha256(hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<(int32_t)sizeof(hash); i++)
      hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    return(hash);
  }
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
  bool komodo_core::komodo_chainactive(uint64_t &height, cryptonote::block &tipindex)
  {
    crypto::hash hash = m_core.get_blockchain_storage().get_db().get_block_hash_from_height(height);
    LOG_PRINT_L3("KomodoValidation::" << __func__);
    cryptonote::block b = m_core.get_blockchain_storage().get_db().get_block(hash);
    crypto::hash tiphash = m_core.get_blockchain_storage().get_db().top_block_hash();
    tipindex = m_core.get_blockchain_storage().get_db().get_block(tiphash);
    uint64_t tipheight = m_core.get_blockchain_storage().get_db().get_block_height(tiphash);
    if (m_core.get_blockchain_storage().get_db().height() != 0)
    {
        if ( height <= m_core.get_blockchain_storage().get_db().height()-1)
          return true;
        else fprintf(stderr,"komodo_chainactive height %lu > active.%lu\n",height,tipheight);
    }
    fprintf(stderr,"komodo_chainactive null chainActive.Tip() height %lu\n",height);
    return false;
  }
  //------------------------------------------------------------------
  int32_t komodo_core::komodo_heightstamp(uint64_t height)
  {
    uint64_t top_block_height = m_core.get_blockchain_storage().get_db().height()-1;
    cryptonote::block *b = nullptr;
    bool activechain = komodo_chainactive(height, *b);
    if (activechain && (top_block_height > 0))
        return(b->timestamp);
    else fprintf(stderr,"komodo_heightstamp null ptr for block.%lu\n",height);
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

} // namespace komodo
} // namespace cryptonote
