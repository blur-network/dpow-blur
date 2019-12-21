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

#pragma once

  char const* Notaries_elected[64][3] =
  {
    {"madmax_NA",          "0237e0d3268cebfa235958808db1efc20cc43b31100813b1f3e15cc5aa647ad2c3", "fd1d3172b91ff9f898dab7626bbf3d45e370e185fe49c09321d72ebc1a1639f5" }, // 0
    {"alright_AR",         "020566fe2fb3874258b2d3cf1809a5d650e0edc7ba746fa5eec72750c5188c9cc9", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"strob_NA",           "0206f7a2e972d9dfef1c424c731503a0a27de1ba7a15a91a362dc7ec0d0fb47685", "60f2567a6b0a1ab57db5d55b581369b9dd05ee32f8a39f5b8cf213c22fb092e8" },
    {"dwy_EU",             "021c7cf1f10c4dc39d13451123707ab780a741feedab6ac449766affe37515a29e", "b70dff34c690235ecb33f961450afbfca429baf1a91e7ceee57881a50c4feba7" },
    {"phm87_SH",           "021773a38db1bc3ede7f28142f901a161c7b7737875edbb40082a201c55dcf0add", "b78a8dc587333a527a3c41d189d7ccdcff5854bbfb1333761bc3cffeb4a0b3cd" },
    {"chainmakers_NA",     "02285d813c30c0bf7eefdab1ff0a8ad08a07a0d26d8b95b3943ce814ac8e24d885", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"indenodes_EU",       "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"blackjok3r_SH",      "021eac26dbad256cbb6f74d41b10763183ee07fb609dbd03480dd50634170547cc", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainmakers_EU",     "03fdf5a3fce8db7dee89724e706059c32e5aa3f233a6b6cc256fea337f05e3dbf7", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"titomane_AR",        "023e3aa9834c46971ff3e7cb86a200ec9c8074a9566a3ea85d400d5739662ee989", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"fullmoon_SH",        "023b7252968ea8a955cd63b9e57dee45a74f2d7ba23b4e0595572138ad1fb42d21", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }, // 10
    {"indenodes_NA",       "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chmex_EU",           "0281304ebbcc39e4f09fda85f4232dd8dacd668e20e5fc11fba6b985186c90086e", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"metaphilibert_SH",   "0284af1a5ef01503e6316a2ca4abf8423a794e9fc17ac6846f042b6f4adedc3309", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"ca333_DEV",          "02856843af2d9457b5b1c907068bef6077ea0904cc8bd4df1ced013f64bf267958", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"cipi_NA",            "02858904a2a1a0b44df4c937b65ee1f5b66186ab87a751858cf270dee1d5031f18", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pungocloud_SH",      "024dfc76fa1f19b892be9d06e985d0c411e60dbbeb36bd100af9892a39555018f6", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"voskcoin_EU",        "034190b1c062a04124ad15b0fa56dfdf34aa06c164c7163b6aec0d654e5f118afb", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"decker_DEV",         "028eea44a09674dda00d88ffd199a09c9b75ba9782382cc8f1e97c0fd565fe5707", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"cryptoeconomy_EU",   "0290ab4937e85246e048552df3e9a66cba2c1602db76e03763e16c671e750145d1", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"etszombi_EU",        "0293ea48d8841af7a419a24d9da11c34b39127ef041f847651bae6ab14dcd1f6b4", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },  // 20
    {"karasugoi_NA",       "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pirate_AR",          "03e29c90354815a750db8ea9cb3c1b9550911bb205f83d0355a061ac47c4cf2fde", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"metaphilibert_AR",   "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"zatjum_SH",          "02d6b0c89cacd58a0af038139a9a90c9e02cd1e33803a1f15fceabea1f7e9c263a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"madmax_AR",          "03c5941fe49d673c094bc8e9bb1a95766b4670c88be76d576e915daf2c30a454d3", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"lukechilds_NA",      "03f1051e62c2d280212481c62fe52aab0a5b23c95de5b8e9ad5f80d8af4277a64b", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"cipi_AR",            "02c4f89a5b382750836cb787880d30e23502265054e1c327a5bfce67116d757ce8", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"tonyl_AR",           "02cc8bc862f2b65ad4f99d5f68d3011c138bf517acdc8d4261166b0be8f64189e1", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"infotech_DEV",       "0345ad4ab5254782479f6322c369cec77a7535d2f2162d103d666917d5e4f30c4c", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"fullmoon_NA",        "032c716701fe3a6a3f90a97b9d874a9d6eedb066419209eed7060b0cc6b710c60b", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },  // 30
    {"etszombi_AR",        "02e55e104aa94f70cde68165d7df3e162d4410c76afd4643b161dea044aa6d06ce", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"node-9_EU",          "0372e5b51e86e2392bb15039bac0c8f975b852b45028a5e43b324c294e9f12e411", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"phba2061_EU",        "03f6bd15dba7e986f0c976ea19d8a9093cb7c989d499f1708a0386c5c5659e6c4e", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"indenodes_AR",       "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"and1-89_EU",         "02736cbf8d7b50835afd50a319f162dd4beffe65f2b1dc6b90e64b32c8e7849ddd", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"komodopioneers_SH",  "032a238a5747777da7e819cfa3c859f3677a2daf14e4dce50916fc65d00ad9c52a", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"komodopioneers_EU",  "036d02425916444fff8cc7203fcbfc155c956dda5ceb647505836bef59885b6866", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"d0ct0r_NA",          "0303725d8525b6f969122faf04152653eb4bf34e10de92182263321769c334bf58", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"kolo_DEV",           "02849e12199dcc27ba09c3902686d2ad0adcbfcee9d67520e9abbdda045ba83227", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"peer2cloud_AR",      "02acc001fe1fe8fd68685ba26c0bc245924cb592e10cec71e9917df98b0e9d7c37", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }, // 40
    {"webworker01_SH",     "031e50ba6de3c16f99d414bb89866e578d963a54bde7916c810608966fb5700776", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"webworker01_NA",     "032735e9cad1bb00eaababfa6d27864fa4c1db0300c85e01e52176be2ca6a243ce", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pbca26_NA",          "03a97606153d52338bcffd1bf19bb69ef8ce5a7cbdc2dbc3ff4f89d91ea6bbb4dc", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"indenodes_SH",       "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"pirate_NA",          "0255e32d8a56671dee8aa7f717debb00efa7f0086ee802de0692f2d67ee3ee06ee", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"lukechilds_AR",      "025c6a73ff6d750b9ddf6755b390948cffdd00f344a639472d398dd5c6b4735d23", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"dragonhound_NA",     "0224a9d951d3a06d8e941cc7362b788bb1237bb0d56cc313e797eb027f37c2d375", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"fullmoon_AR",        "03da64dd7cd0db4c123c2f79d548a96095a5a103e5b9d956e9832865818ffa7872", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainzilla_SH",      "0360804b8817fd25ded6e9c0b50e3b0782ac666545b5416644198e18bc3903d9f9", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"titomane_EU",        "03772ac0aad6b0e9feec5e591bff5de6775d6132e888633e73d3ba896bdd8e0afb", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }, // 50
    {"jeezy_EU",           "037f182facbad35684a6e960699f5da4ba89e99f0d0d62a87e8400dd086c8e5dd7", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"titomane_SH",        "03850fdddf2413b51790daf51dd30823addb37313c8854b508ea6228205047ef9b", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"alien_AR",           "03911a60395801082194b6834244fa78a3c30ff3e888667498e157b4aa80b0a65f", "c1bbb2a4cc2bc83a8763768bc4b038d58ec805d533d2bbbc548a08bb367c25e4" },
    {"pirate_EU",          "03fff24efd5648870a23badf46e26510e96d9e79ce281b27cfe963993039dd1351", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"thegaltmines_NA",    "02db1a16c7043f45d6033ccfbd0a51c2d789b32db428902f98b9e155cf0d7910ed", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"computergenie_NA",   "03a78ae070a5e9e935112cf7ea8293f18950f1011694ea0260799e8762c8a6f0a4", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"nutellalicka_SH",    "02f7d90d0510c598ce45915e6372a9cd0ba72664cb65ce231f25d526fc3c5479fc", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"chainstrike_SH",     "03b806be3bf7a1f2f6290ec5c1ea7d3ea57774dcfcf2129a82b2569e585100e1cb", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"dwy_SH",             "036536d2d52d85f630b68b050f29ea1d7f90f3b42c10f8c5cdf3dbe1359af80aff", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"alien_EU",           "03bb749e337b9074465fa28e757b5aa92cb1f0fea1a39589bca91a602834d443cd", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }, // 60
    {"gt_AR",              "0348430538a4944d3162bb4749d8c5ed51299c2434f3ee69c11a1f7815b3f46135", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"patchkez_SH",        "03f45e9beb5c4cd46525db8195eb05c1db84ae7ef3603566b3d775770eba3b96ee", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" },
    {"decker_AR",          "03ffdf1a116300a78729608d9930742cd349f11a9d64fcc336b8f18592dd9c91bc", "89db1c9b679ad4cf891b59dff91e03c88961f90bc51040eec70cbdbe8b738572" }, // 63
  };

#endif
