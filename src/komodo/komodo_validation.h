/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

// Parts of this file have been modified for compatibility with the Blur Nework
// The copyright notice below applies to only those portions that have been changed.
//
// Copyright (c) Blur Network, 2018-2019
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

// in init.cpp at top of AppInitParameterInteraction()
// int32_t komodo_init();
// komodo_init();

// in validation.cpp
// at end of ConnectBlock: komodo_connectblock(pindex,*(CBlock *)&block);
// at beginning DisconnectBlock: komodo_disconnect((CBlockIndex *)pindex,(CBlock *)&block);
/* add to ContextualCheckBlockHeader
    uint256 hash = block.GetHash();
    int32_t notarized_height;
    ....
    else if ( komodo_checkpoint(&notarized_height,(int32_t)nHeight,hash) < 0 )
    {
        CBlockIndex *heightblock = chainActive[nHeight];
        if ( heightblock != 0 && heightblock->GetBlockHash() == hash )
        {
            //fprintf(stderr,"got a pre notarization block that matches height.%d\n",(int32_t)nHeight);
            return true;
        } else return state.DoS(100, error("%s: forked chain %d older than last notarized (height %d) vs %d", __func__,nHeight, notarized_height));
    }
*/
#include "cryptonote_core/blockchain.h"
#include "crypto/crypto.h"
#include "crypto/hash-ops.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "komodo_rpcblockchain.h"
#include "bitcoin/bitcoin.h"
#include "rpc/core_rpc_server.h"
#include <limits.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>

#ifdef _MSC_VER
#include <malloc.h>
#elif !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__DragonFly__)
 #include <alloca.h>
#else
 #include <stdlib.h>
#endif

static const uint64_t SATOSHIDEN = ((uint64_t)100000000L);
#define dstr(x) ((double)(x) / SATOSHIDEN)
#define portable_mutex_t pthread_mutex_t
#define portable_mutex_init(ptr) pthread_mutex_init(ptr,NULL)
#define portable_mutex_lock pthread_mutex_lock
#define portable_mutex_unlock pthread_mutex_unlock

static const char* CRYPTO777_PUBSECPSTR[33] = { "020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9" };
static const uint64_t KOMODO_MINRATIFY = 11;
static const uint64_t  KOMODO_ELECTION_GAP = 2000;
static const uint64_t  KOMODO_ASSETCHAIN_MAXLEN = 64;
static const uint64_t  KOMODO_NOTARIES_TIMESTAMP1 = 1525132800; // May 1st 2018 1530921600 // 7/7/2017
static const uint64_t  KOMODO_NOTARIES_HEIGHT1 = ((814000 / KOMODO_ELECTION_GAP) * KOMODO_ELECTION_GAP);

union _bits256 { uint8_t bytes[32]; uint16_t ushorts[16]; uint32_t uints[8]; uint64_t ulongs[4]; uint64_t txid;};
typedef union _bits256 bits256;

struct sha256_vstate { uint64_t length; uint32_t state[8],curlen; uint8_t buf[64]; };
struct rmd160_vstate { uint64_t length; uint8_t buf[64]; uint32_t curlen, state[5]; };

namespace komodo {

class komodo_core
{
  public:
    komodo_core(cryptonote::core& cr, nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>& p2p);

  int32_t komodo_chainactive_timestamp();
  bool komodo_chainactive(uint64_t &height, cryptonote::block &b);
  int32_t komodo_heightstamp(uint64_t height);
//  size_t tree_hash_count(size_t count);
  void komodo_disconnect(uint64_t height,cryptonote::block block);
  int32_t komodo_notarized_height(uint64_t *prevMoMheightp, uint256 *hashp,uint256 *txidp);
  int32_t komodo_notarizeddata(uint64_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp);
  void komodo_notarized_update(uint64_t nHeight,uint64_t notarized_height,uint256 notarized_hash,uint256 notarized_desttxid,uint256 MoM,int32_t MoMdepth);
  int32_t komodo_checkpoint(int32_t *notarized_heightp, int32_t nHeight, crypto::hash hash);
  void komodo_voutupdate(int32_t txi,int32_t vout,uint8_t *scriptbuf,int32_t scriptlen,int32_t height,int32_t *specialtxp,int32_t *notarizedheightp,uint64_t value,int32_t notarized,uint64_t signedmask);
  void komodo_connectblock(uint64_t& height,cryptonote::block& b);
  int32_t komodo_init();
  int32_t komodo_notaries(uint8_t pubkeys[64][33],uint64_t height,uint64_t timestamp);

  private:
    cryptonote::core& m_core;
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>& m_p2p;
    bool check_core_ready();
    bool check_core_busy();

};

  const char ASSETCHAINS_SYMBOL[5] = { "BLUR" };

  struct notarized_checkpoint *komodo_npptr(uint64_t height);
  int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp);
  int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp);
  bits256 iguana_merkle(bits256 *root_hash, int txn_count);
    void komodo_importpubkeys();
  void komodo_clearstate();
  int32_t komodo_importaddress(std::string addr);
  uint256 komodo_calcMoM(uint64_t height,int32_t MoMdepth);


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
#define MIN(x, y) ( ((x)<(y))?(x):(y) )

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
            n = MIN(inlen,64 - md->curlen);
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

void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len)
{
    struct sha256_vstate md;
    sha256_vinit(&md);
    sha256_vprocess(&md,src,len);
    sha256_vdone(&md,hash);
}

bits256 bits256_doublesha256(char *deprecated,uint8_t *data,int32_t datalen)
{
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(0,hash.bytes,data,datalen);
    vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<(int32_t)sizeof(hash); i++)
        hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    return(hash);
}

int32_t bitweight(uint64_t x)
{
    int i,wt = 0;
    for (i=0; i<64; i++)
        if ( (1LL << i) & x )
            wt++;
    return(wt);
}

int32_t _unhex(char c)
{
    if ( c >= '0' && c <= '9' )
        return(c - '0');
    else if ( c >= 'a' && c <= 'f' )
        return(c - 'a' + 10);
    else if ( c >= 'A' && c <= 'F' )
        return(c - 'A' + 10);
    return(-1);
}

int32_t is_hexstr(char *str,int32_t n)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
    {
        if ( n > 0 && i >= n )
            break;
        if ( _unhex(str[i]) < 0 )
            break;
    }
    if ( n == 0 )
        return(i);
    return(i == n);
}

int32_t unhex(char c)
{
    int32_t hex;
    if ( (hex= _unhex(c)) < 0 )
    {
        //printf("unhex: illegal hexchar.(%c)\n",c);
    }
    return(hex);
}

unsigned char _decode_hex(char *hex) { return((unhex(hex[0])<<4) | unhex(hex[1])); }

int32_t decode_hex(uint8_t *bytes,int32_t n,char *hex)
{
    int32_t adjust,i = 0;
    //printf("decode.(%s)\n",hex);
    if ( is_hexstr(hex,n) <= 0 )
    {
        memset(bytes,0,n);
        return(n);
    }
    if ( hex[n-1] == '\n' || hex[n-1] == '\r' )
        hex[--n] = 0;
    if ( n == 0 || (hex[n*2+1] == 0 && hex[n*2] != 0) )
    {
        if ( n > 0 )
        {
            bytes[0] = unhex(hex[0]);
            printf("decode_hex n.%d hex[0] (%c) -> %d hex.(%s) [n*2+1: %d] [n*2: %d %c] len.%ld\n",n,hex[0],bytes[0],hex,hex[n*2+1],hex[n*2],hex[n*2],(long)strlen(hex));
        }
        bytes++;
        hex++;
        adjust = 1;
    } else adjust = 0;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
            bytes[i] = _decode_hex(&hex[i*2]);
    }
    //bytes[i] = 0;
    return(n + adjust);
}

char hexbyte(int32_t c)
{
    c &= 0xf;
    if ( c < 10 )
        return('0'+c);
    else if ( c < 16 )
        return('a'+c-10);
    else return(0);
}

int32_t init_hexbytes_noT(char *hexbytes,unsigned char *message,long len)
{
    int32_t i;
    if ( len <= 0 )
    {
        hexbytes[0] = 0;
        return(1);
    }
    for (i=0; i<len; i++)
    {
        hexbytes[i*2] = hexbyte((message[i]>>4) & 0xf);
        hexbytes[i*2 + 1] = hexbyte(message[i] & 0xf);
        //printf("i.%d (%02x) [%c%c]\n",i,message[i],hexbytes[i*2],hexbytes[i*2+1]);
    }
    hexbytes[len*2] = 0;
    //printf("len.%ld\n",len*2+1);
    return((int32_t)len*2+1);
}

const char *Notaries_elected0[][2] =
{
    { "0_jl777_testA", "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" },
    { "0_jl777_testB", "02ebfc784a4ba768aad88d44d1045d240d47b26e248cafaf1c5169a42d7a61d344" },
    { "0_kolo_testA", "0287aa4b73988ba26cf6565d815786caf0d2c4af704d7883d163ee89cd9977edec" },
    { "artik_AR", "029acf1dcd9f5ff9c455f8bb717d4ae0c703e089d16cf8424619c491dff5994c90" },
    { "artik_EU", "03f54b2c24f82632e3cdebe4568ba0acf487a80f8a89779173cdb78f74514847ce" },
    { "artik_NA", "0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842" },
    { "artik_SH", "02bdd8840a34486f38305f311c0e2ae73e84046f6e9c3dd3571e32e58339d20937" },
    { "badass_EU", "0209d48554768dd8dada988b98aca23405057ac4b5b46838a9378b95c3e79b9b9e" },
    { "badass_NA", "02afa1a9f948e1634a29dc718d218e9d150c531cfa852843a1643a02184a63c1a7" },
    { "badass_SH", "026b49dd3923b78a592c1b475f208e23698d3f085c4c3b4906a59faf659fd9530b" },
    { "crackers_EU", "03bc819982d3c6feb801ec3b720425b017d9b6ee9a40746b84422cbbf929dc73c3" }, // 10
    { "crackers_NA", "03205049103113d48c7c7af811b4c8f194dafc43a50d5313e61a22900fc1805b45" },
    { "crackers_SH", "02be28310e6312d1dd44651fd96f6a44ccc269a321f907502aae81d246fabdb03e" },
    { "durerus_EU", "02bcbd287670bdca2c31e5d50130adb5dea1b53198f18abeec7211825f47485d57" },
    { "etszombi_AR", "031c79168d15edabf17d9ec99531ea9baa20039d0cdc14d9525863b83341b210e9" },
    { "etszombi_EU", "0281b1ad28d238a2b217e0af123ce020b79e91b9b10ad65a7917216eda6fe64bf7" }, // 15
    { "etszombi_SH", "025d7a193c0757f7437fad3431f027e7b5ed6c925b77daba52a8755d24bf682dde" },
    { "farl4web_EU", "0300ecf9121cccf14cf9423e2adb5d98ce0c4e251721fa345dec2e03abeffbab3f" },
    { "farl4web_SH", "0396bb5ed3c57aa1221d7775ae0ff751e4c7dc9be220d0917fa8bbdf670586c030" },
    { "fullmoon_AR", "0254b1d64840ce9ff6bec9dd10e33beb92af5f7cee628f999cb6bc0fea833347cc" },
    { "fullmoon_NA", "031fb362323b06e165231c887836a8faadb96eda88a79ca434e28b3520b47d235b" }, // 20
    { "fullmoon_SH", "030e12b42ec33a80e12e570b6c8274ce664565b5c3da106859e96a7208b93afd0d" },
    { "grewal_NA", "03adc0834c203d172bce814df7c7a5e13dc603105e6b0adabc942d0421aefd2132" },
    { "grewal_SH", "03212a73f5d38a675ee3cdc6e82542a96c38c3d1c79d25a1ed2e42fcf6a8be4e68" },
    { "indenodes_AR", "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147" },
    { "indenodes_EU", "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c" },
    { "indenodes_NA", "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988" },
    { "indenodes_SH", "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e" },
    { "jeezy_EU", "023cb3e593fb85c5659688528e9a4f1c4c7f19206edc7e517d20f794ba686fd6d6" },
    { "jsgalt_NA", "027b3fb6fede798cd17c30dbfb7baf9332b3f8b1c7c513f443070874c410232446" },
    { "karasugoi_NA", "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982" }, // 30
    { "kashifali_EU", "033777c52a0190f261c6f66bd0e2bb299d30f012dcb8bfff384103211edb8bb207" },
    { "kolo_AR", "03016d19344c45341e023b72f9fb6e6152fdcfe105f3b4f50b82a4790ff54e9dc6" },
    { "kolo_SH", "02aa24064500756d9b0959b44d5325f2391d8e95c6127e109184937152c384e185" },
    { "metaphilibert_AR", "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6" },
    { "movecrypto_AR", "022783d94518e4dc77cbdf1a97915b29f427d7bc15ea867900a76665d3112be6f3" },
    { "movecrypto_EU", "021ab53bc6cf2c46b8a5456759f9d608966eff87384c2b52c0ac4cc8dd51e9cc42" },
    { "movecrypto_NA", "02efb12f4d78f44b0542d1c60146738e4d5506d27ec98a469142c5c84b29de0a80" },
    { "movecrypto_SH", "031f9739a3ebd6037a967ce1582cde66e79ea9a0551c54731c59c6b80f635bc859" },
    { "muros_AR", "022d77402fd7179335da39479c829be73428b0ef33fb360a4de6890f37c2aa005e" },
    { "noashh_AR", "029d93ef78197dc93892d2a30e5a54865f41e0ca3ab7eb8e3dcbc59c8756b6e355" }, // 40
    { "noashh_EU", "02061c6278b91fd4ac5cab4401100ffa3b2d5a277e8f71db23401cc071b3665546" },
    { "noashh_NA", "033c073366152b6b01535e15dd966a3a8039169584d06e27d92a69889b720d44e1" },
    { "nxtswe_EU", "032fb104e5eaa704a38a52c126af8f67e870d70f82977e5b2f093d5c1c21ae5899" },
    { "polycryptoblog_NA", "02708dcda7c45fb54b78469673c2587bfdd126e381654819c4c23df0e00b679622" },
    { "pondsea_AR", "032e1c213787312099158f2d74a89e8240a991d162d4ce8017d8504d1d7004f735" },
    { "pondsea_EU", "0225aa6f6f19e543180b31153d9e6d55d41bc7ec2ba191fd29f19a2f973544e29d" },
    { "pondsea_NA", "031bcfdbb62268e2ff8dfffeb9ddff7fe95fca46778c77eebff9c3829dfa1bb411" },
    { "pondsea_SH", "02209073bc0943451498de57f802650311b1f12aa6deffcd893da198a544c04f36" },
    { "popcornbag_AR", "02761f106fb34fbfc5ddcc0c0aa831ed98e462a908550b280a1f7bd32c060c6fa3" },
    { "popcornbag_NA", "03c6085c7fdfff70988fda9b197371f1caf8397f1729a844790e421ee07b3a93e8" }, // 50
    { "ptytrader_NA", "0328c61467148b207400b23875234f8a825cce65b9c4c9b664f47410b8b8e3c222" },
    { "ptytrader_SH", "0250c93c492d8d5a6b565b90c22bee07c2d8701d6118c6267e99a4efd3c7748fa4" },
    { "rnr_AR", "029bdb08f931c0e98c2c4ba4ef45c8e33a34168cb2e6bf953cef335c359d77bfcd" },
    { "rnr_EU", "03f5c08dadffa0ffcafb8dd7ffc38c22887bd02702a6c9ac3440deddcf2837692b" },
    { "rnr_NA", "02e17c5f8c3c80f584ed343b8dcfa6d710dfef0889ec1e7728ce45ce559347c58c" },
    { "rnr_SH", "037536fb9bdfed10251f71543fb42679e7c52308bcd12146b2568b9a818d8b8377" },
    { "titomane_AR", "03cda6ca5c2d02db201488a54a548dbfc10533bdc275d5ea11928e8d6ab33c2185" },
    { "titomane_EU", "02e41feded94f0cc59f55f82f3c2c005d41da024e9a805b41105207ef89aa4bfbd" },
    { "titomane_SH", "035f49d7a308dd9a209e894321f010d21b7793461b0c89d6d9231a3fe5f68d9960" },
    { "vanbreuk_EU", "024f3cad7601d2399c131fd070e797d9cd8533868685ddbe515daa53c2e26004c3" }, // 60
    { "xrobesx_NA", "03f0cc6d142d14a40937f12dbd99dbd9021328f45759e26f1877f2a838876709e1" },
    { "xxspot1_XX", "02ef445a392fcaf3ad4176a5da7f43580e8056594e003eba6559a713711a27f955" },
    { "xxspot2_XX", "03d85b221ea72ebcd25373e7961f4983d12add66a92f899deaf07bab1d8b6f5573" }
};

const char *Notaries_elected1[][4] =
{
    {"0dev1_jl777"       , "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" , "RNJmgYaFF5DbnrNUX6pMYz9rcnDKC2tuAc"},
    {"0dev2_kolo"        , "030f34af4b908fb8eb2099accb56b8d157d49f6cfb691baa80fdd34f385efed961" , "RLj9h7zfnx4X9hvquR3sEwzHvcvF61W2Rc"},
    {"0dev3_kolo"        , "025af9d2b2a05338478159e9ac84543968fd18c45fd9307866b56f33898653b014" , "RTZi9uC1wEu3PD9eoL4R7KyeAse7uvdHuS"},
    {"0dev4_decker"      , "028eea44a09674dda00d88ffd199a09c9b75ba9782382cc8f1e97c0fd565fe5707" , "RDECKVXcWCgPpMrKqQmMX7PxzQVLCzcR5a"},
    {"a-team_SH"         , "03b59ad322b17cb94080dc8e6dc10a0a865de6d47c16fb5b1a0b5f77f9507f3cce" , "RSuXRScqHNbRFqjur2C3tf3oDoauBs2B1i"},
    {"artik_AR"          , "029acf1dcd9f5ff9c455f8bb717d4ae0c703e089d16cf8424619c491dff5994c90" , "RXF3aHUaWDUY4fRRYmBNALoHWkgSQCiJ4f"},
    {"artik_EU"          , "03f54b2c24f82632e3cdebe4568ba0acf487a80f8a89779173cdb78f74514847ce" , "RL2SkPSCGMvcHqZ56ErfMxbQGdA4nk7MZp"},
    {"artik_NA"          , "0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842" , "RFssbc211PJdVy1bvcvAG5X2N4ovPAoy5o"},
    {"artik_SH"          , "02bdd8840a34486f38305f311c0e2ae73e84046f6e9c3dd3571e32e58339d20937" , "RNoz2DKPZ2ppMxgYx5tce9sjZBHefvPvNB"},
    {"badass_EU"         , "0209d48554768dd8dada988b98aca23405057ac4b5b46838a9378b95c3e79b9b9e" , "RVxtoUT9CXbC1LdhztNAf9yR5ySnFnSPQh"},
    {"badass_NA"         , "02afa1a9f948e1634a29dc718d218e9d150c531cfa852843a1643a02184a63c1a7" , "R9XBrbj8iKkwy9M4erUqRaBinAiZSTXav3"},
    {"batman_AR"         , "033ecb640ec5852f42be24c3bf33ca123fb32ced134bed6aa2ba249cf31b0f2563" , "RVvcVXkqWmMmjQdFnqwQbtPrdU7DFpHA3G"},
    {"batman_SH"         , "02ca5898931181d0b8aafc75ef56fce9c43656c0b6c9f64306e7c8542f6207018c" , "RY5TZSnmtGZLFMpnJTE6gDRyk1zDvMktcc"},
    {"ca333_EU"          , "03fc87b8c804f12a6bd18efd43b0ba2828e4e38834f6b44c0bfee19f966a12ba99" , "RUvwCVA1NfDB6ZWrEgVYZHWGjMzpxm19r1"},
    {"chainmakers_EU"    , "02f3b08938a7f8d2609d567aebc4989eeded6e2e880c058fdf092c5da82c3bc5ee" , "RSQUoSfM7R7SnatK6Udsb5t39movCpUKQE"},
    {"chainmakers_NA"    , "0276c6d1c65abc64c8559710b8aff4b9e33787072d3dda4ec9a47b30da0725f57a" , "RLF3sBrXAdofwDnS2114mkBMSBeJDd5Doy"},
    {"chainstrike_SH"    , "0370bcf10575d8fb0291afad7bf3a76929734f888228bc49e35c5c49b336002153" , "RXrQPqU4SwARri1m2n7232TDECvjzXCJh4"},
    {"cipi_AR"           , "02c4f89a5b382750836cb787880d30e23502265054e1c327a5bfce67116d757ce8" , "RBZxvAMqt1QhkvmiMRqDGRBW9QaQjqPEpF"},
    {"cipi_NA"           , "02858904a2a1a0b44df4c937b65ee1f5b66186ab87a751858cf270dee1d5031f18" , "RD2uPC7aUkX9tQTYgRvDb2HQPWa22VttEE"},
    {"crackers_EU"       , "03bc819982d3c6feb801ec3b720425b017d9b6ee9a40746b84422cbbf929dc73c3" , "RA7nJEoqNGu13P7Gv4mWfoJTmpZ9ac2Bh2"},
    {"crackers_NA"       , "03205049103113d48c7c7af811b4c8f194dafc43a50d5313e61a22900fc1805b45" , "RQcBfvJLyB96GCuTBRUNckQESw8LYjHQaC"},
    {"dwy_EU"            , "0259c646288580221fdf0e92dbeecaee214504fdc8bbdf4a3019d6ec18b7540424" , "RWVt3CDvXXAw5NeyMrjUC8s7YssAJ9j4A4"},
    {"emmanux_SH"        , "033f316114d950497fc1d9348f03770cd420f14f662ab2db6172df44c389a2667a" , "RBHCkuYMUbQph7MZsHcZYfGfyqBm8Y4jFQ"},
    {"etszombi_EU"       , "0281b1ad28d238a2b217e0af123ce020b79e91b9b10ad65a7917216eda6fe64bf7" , "RPjUmFNcWEW9Bu275kPxzRXyWDz6bfQpPD"},
    {"fullmoon_AR"       , "03380314c4f42fa854df8c471618751879f9e8f0ff5dbabda2bd77d0f96cb35676" , "RAtXFwGsgtsHJGuKhJBMbB8vri3SRVQYeu"},
    {"fullmoon_NA"       , "030216211d8e2a48bae9e5d7eb3a42ca2b7aae8770979a791f883869aea2fa6eef" , "RAtyzPtx7yeH7jhFkD7e2dhf2p429Cn3tQ"},
    {"fullmoon_SH"       , "03f34282fa57ecc7aba8afaf66c30099b5601e98dcbfd0d8a58c86c20d8b692c64" , "R9WsywChUgTumbK2cf1RdjHrWMZV3nfs3a"},
    {"goldenman_EU"      , "02d6f13a8f745921cdb811e32237bb98950af1a5952be7b3d429abd9152f8e388d" , "RHzbQkW7oLK43GKEPK78rSCs7WDiaa4dbw"},
    {"indenodes_AR"      , "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147" , "RFQNjTfcvSAmf8D83og1NrdHj1wH2fc5X4"},
    {"indenodes_EU"      , "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c" , "RPknkGAHMwUBvfKQfvw9FyatTZzicSiN4y"},
    {"indenodes_NA"      , "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988" , "RMqbQz4NPNbG15QBwy9EFvLn4NX5Fa7w5g"},
    {"indenodes_SH"      , "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e" , "RQipE6ycbVVb9vCkhqrK8PGZs2p5YmiBtg"},
    {"jackson_AR"        , "038ff7cfe34cb13b524e0941d5cf710beca2ffb7e05ddf15ced7d4f14fbb0a6f69" , "RUc5sa136Agwb9dSfMKn1oc7myHkUzeZf4"},
    {"jeezy_EU"          , "023cb3e593fb85c5659688528e9a4f1c4c7f19206edc7e517d20f794ba686fd6d6" , "RCA8H1npFPW5pnJRzycF8tFEJmn6XZhD4j"},
    {"karasugoi_NA"      , "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982" , "RJD5jRidYW9Cu8qxjg9HDCsx6J3A4wQ4LU"},
    {"komodoninja_EU"    , "038e567b99806b200b267b27bbca2abf6a3e8576406df5f872e3b38d30843cd5ba" , "RWgpXEycP4rVkFp3j7WzV6E2LfR842WswN"},
    {"komodoninja_SH"    , "033178586896915e8456ebf407b1915351a617f46984001790f0cce3d6f3ada5c2" , "RVAUHZ4QGzxmW815b98oMv943FCms6AzUi"},
    {"komodopioneers_SH" , "033ace50aedf8df70035b962a805431363a61cc4e69d99d90726a2d48fb195f68c" , "RGxBQho3stt6EiApWTzFZxDvqqsM8GwAuk"},
    {"libscott_SH"       , "03301a8248d41bc5dc926088a8cf31b65e2daf49eed7eb26af4fb03aae19682b95" , "RHuUpCbaGbv27fsjC1p6xwtwRzKQ1exqaA"},
    {"lukechilds_AR"     , "031aa66313ee024bbee8c17915cf7d105656d0ace5b4a43a3ab5eae1e14ec02696" , "RPxsaGNqTKzPnbm5q7QXwu7b6EZWuLxJG3"},
    {"madmax_AR"         , "03891555b4a4393d655bf76f0ad0fb74e5159a615b6925907678edc2aac5e06a75" , "RQ5JmyvjzGMxZvs2auTabXVQeuxrA2oBjy"},
    {"meshbits_AR"       , "02957fd48ae6cb361b8a28cdb1b8ccf5067ff68eb1f90cba7df5f7934ed8eb4b2c" , "RV8Khq8SbYQALx9eMQ8meseWpFiZS8seL1"},
    {"meshbits_SH"       , "025c6e94877515dfd7b05682b9cc2fe4a49e076efe291e54fcec3add78183c1edb" , "RH1vUjh6JBX7dpPR3C89U8hzErp1uoa2by"},
    {"metaphilibert_AR"  , "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6" , "RKdXYhrQxB3LtwGpysGenKFHFTqSi5g7EF"},
    {"metaphilibert_SH"  , "0284af1a5ef01503e6316a2ca4abf8423a794e9fc17ac6846f042b6f4adedc3309" , "RRrqjqDPZ9XC6xJMeKgf7GNHjiU88hJQ16"},
    {"patchkez_SH"       , "0296270f394140640f8fa15684fc11255371abb6b9f253416ea2734e34607799c4" , "RBp1xHCAb3XcLAV49F8wUYw3aBvhHKKEwa"},
    {"pbca26_NA"         , "0276aca53a058556c485bbb60bdc54b600efe402a8b97f0341a7c04803ce204cb5" , "REX8jNcUki4NyNde3ovr5ZgjwnCyRZYczv"},
    {"peer2cloud_AR"     , "034e5563cb885999ae1530bd66fab728e580016629e8377579493b386bf6cebb15" , "RH2Tuan5wt9x19aBPgTHPtkh2koWCEsjEK"},
    {"peer2cloud_SH"     , "03396ac453b3f23e20f30d4793c5b8ab6ded6993242df4f09fd91eb9a4f8aede84" , "RSp8vhyL6hN3yqn5V1qje62pBgBE9fv3Eh"},
    {"polycryptoblog_NA" , "02708dcda7c45fb54b78469673c2587bfdd126e381654819c4c23df0e00b679622" , "RE3P8D8rcWZBeKmT8DURPdezW87MU5Ho3F"},
    {"hyper_AR"          , "020f2f984d522051bd5247b61b080b4374a7ab389d959408313e8062acad3266b4" , "RTWpNfpcQgGYnrtgdUyqoPiF9r2CJoAw6Z"},
    {"hyper_EU"          , "03d00cf9ceace209c59fb013e112a786ad583d7de5ca45b1e0df3b4023bb14bf51" , "RQMyeeSyKFUTd7cYTM1Fq7nSt6zJZKNubi"},
    {"hyper_SH"          , "0383d0b37f59f4ee5e3e98a47e461c861d49d0d90c80e9e16f7e63686a2dc071f3" , "RFCZc3SnyEtUTSVDkHEvrm7tCdhiDMufLx"},
    {"hyper_NA"          , "03d91c43230336c0d4b769c9c940145a8c53168bf62e34d1bccd7f6cfc7e5592de" , "RTdEgZV1QEsBTphiRRdk4FcstTBJ8wAkRX"},
    {"popcornbag_AR"     , "02761f106fb34fbfc5ddcc0c0aa831ed98e462a908550b280a1f7bd32c060c6fa3" , "RWPhKTa5Huepz19TYrxAE65rQn3D3xPrNw"},
    {"popcornbag_NA"     , "03c6085c7fdfff70988fda9b197371f1caf8397f1729a844790e421ee07b3a93e8" , "RVQAwUJdFVVK2Pjiq4rYkvMSiZucHtJA7X"},
    {"alien_AR"          , "0348d9b1fc6acf81290405580f525ee49b4749ed4637b51a28b18caa26543b20f0" , "RBHzJTW73U3nyHyxBwiG92bJckxZowPY87"},
    {"alien_EU"          , "020aab8308d4df375a846a9e3b1c7e99597b90497efa021d50bcf1bbba23246527" , "RUdfZrpAhYyT4LVz6Vyj2K14yK1uC2K4Dz"},
    {"thegaltmines_NA"   , "031bea28bec98b6380958a493a703ddc3353d7b05eb452109a773eefd15a32e421" , "RAusaHRqdMmML3szif3Wai1ZSEWCyu7X9Y"},
    {"titomane_AR"       , "029d19215440d8cb9cc6c6b7a4744ae7fb9fb18d986e371b06aeb34b64845f9325" , "RWk4WLiAv6MKWLozJbj1jyhayKtjwbtX7M"},
    {"titomane_EU"       , "0360b4805d885ff596f94312eed3e4e17cb56aa8077c6dd78d905f8de89da9499f" , "RCTgouafkve3rCSaqmm89TUpKGvQSTFr5M"},
    {"titomane_SH"       , "03573713c5b20c1e682a2e8c0f8437625b3530f278e705af9b6614de29277a435b" , "RAqoFL81YGFJ7hidAYUw2rzX8wjFKPCecP"},
    {"webworker01_NA"    , "03bb7d005e052779b1586f071834c5facbb83470094cff5112f0072b64989f97d7" , "RMbNsa4Nf3BAd16BQaAAmfzAgnuorUDrCr"},
    {"xrobesx_NA"        , "03f0cc6d142d14a40937f12dbd99dbd9021328f45759e26f1877f2a838876709e1" , "RLQoAcs1RaqW1xfN2NJwoZWW5twexPhuGB"},
};

std::string NOTARY_PUBKEY;
uint8_t NOTARY_PUBKEY33[33];
uint256 NOTARIZED_HASH,NOTARIZED_DESTTXID,NOTARIZED_MOM;
portable_mutex_t komodo_mutex;

uint256 komodo_calcMoM(uint64_t height,int32_t MoMdepth)
{
    static uint256 zero;
    bits256 *MoM, *tree;
    std::vector<cryptonote::transaction> txs;
    std::vector<cryptonote::block> blocks;
    int32_t i;

    if ( MoMdepth >= height )
        return(zero);

    tree = (bits256*)calloc(MoMdepth * 3,sizeof(*tree));

    for (i=0; i < MoMdepth; i++)
    {

       cryptonote::block block;
//        if (komodo_core::komodo_chainactive(height - i, &block) == 0) {
//            free(tree);
            return(zero);
//        }
//          std::string merkle_str = epee::string_tools::pod_to_hex(cryptonote::get_tx_tree_hash(blocks[i].tx_hashes));
//          std::vector<uint8_t> merkle = hex_to_bytes256(merkle_str);
//          merkles.push_back(merkle);
    }
    memset(MoM, 0, crypto::HASH_SIZE);
//    iguana_merkle(blocks[i],MoMdepth);
    return(*(uint256*)MoM);
}


} //namespace komodo
