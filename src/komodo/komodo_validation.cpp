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

// Parts of this file have been modified for compatibility with the Blur Nework.
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

#include "komodo_validation.h"
#include "cryptonote_core/blockchain.h"
#include "common/hex_str.h"
#include "crypto/crypto.h"
#include "p2p/net_node.h"
#include "crypto/hash-ops.h"
#include "p2p/net_node.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "komodo_notaries.h"
#include "komodo_notary_server/notary_server.h"
#include "bitcoin/bitcoin.h"
#include "libbtc/include/btc/tool.h"
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

void ImportAddress(btc_wallet* pwallet, char* p2pkh_address, const std::string& strLabel, const char* pubkey_hex)
{
  char filepath;
  int error = 0;
  btc_bool created = false;
  btc_wallet_load(pwallet, &filepath, &error, &created);
  extern const btc_chainparams btc_chainparams_main;
  addresses_from_pubkey(&btc_chainparams_main, pubkey_hex, p2pkh_address, nullptr, nullptr);
}


int32_t KOMODO_TXINDEX = 1;

/*
int32_t gettxout_scriptPubKey(int32_t height,uint8_t *scriptPubKey,int32_t maxsize, btc_uint256 txid,int32_t n)
{
    static btc_uint256 zero; int32_t i,m; uint8_t *ptr; btc_tx tx; btc_uint256 hashBlock;
    btc_tx txref=0;
    LOCK(cs_main);
    if ( KOMODO_TXINDEX != 0 )
    {
        if ( GetTransaction(txid,tx,hashBlock,false) == 0 )
        {
            fprintf(stderr,"ht.%d couldnt get txid.%s\n",height,txid.GetHex().c_str());
            return(-1);
        }
    }
    else
    {
        btc_wallet * const pwallet = vpwallets[0];
        if ( pwallet != 0 )
        {
            auto it = pwallet->mapWallet.find(txid);
            if ( it != pwallet->mapWallet.end() )
            {
                const CWalletTx& wtx = it->second;
                txref = wtx.tx;
                fprintf(stderr,"found tx in wallet\n");
            }
        }
    }

    if ( txref != 0 && n >= 0 && n <= (int32_t)txref->vout.size() ) // vout.size() seems off by 1
    {
        ptr = (uint8_t *)txref->vout[n].scriptPubKey.data();
        m = txref->vout[n].scriptPubKey.size();
        for (i=0; i<maxsize&&i<m; i++)
            scriptPubKey[i] = ptr[i];
        fprintf(stderr,"got scriptPubKey[%d] via rawtransaction ht.%d %s\n",m,height,txid.GetHex().c_str());
        return(i);
    }
    else if ( txref != 0 )
        fprintf(stderr,"gettxout_scriptPubKey ht.%d n.%d > voutsize.%d\n",height,n,(int32_t)txref->vout.size());

    return(-1);
}
*/

int32_t komodo_importaddress(char* addr)
{
    std::vector<btc_wallet*> vpwallets;
    vector* addr_out = nullptr;
    int i = 0;
    btc_wallet* pwallet; // this needs initialized properly... 
    btc_wallet_get_addresses(pwallet, addr_out);
    ssize_t found = vector_find(addr_out, addr);
    if (found != 0)
    {
      printf("komodo_importaddress %s already there\n", addr);
      return(0);
    }
    else
    {
      printf("komodo_importaddress %s\n",addr);
      ImportAddress(pwallet, addr, NULL, NULL);
      return (1);
    }

    MERROR("komodo_importaddress failed" << addr);
    return(-1);
}



namespace cryptonote {

namespace komodo {

std::string NOTARY_PUBKEY;
uint8_t NOTARY_PUBKEY33[33];
portable_mutex_t komodo_mutex;
int32_t NUM_NPOINTS,last_NPOINTSi,NOTARIZED_HEIGHT,NOTARIZED_MOMDEPTH,KOMODO_NEEDPUBKEYS;
uint256 NOTARIZED_HASH, NOTARIZED_MOM, NOTARIZED_DESTTXID;


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
  //------------------------------------------------------------------



int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    int32_t i; uint64_t x;
    if ( rwflag == 0 )
    {
        x = 0;
        for (i=len-1; i>=0; i--)
        {
            x <<= 8;
            x |= serialized[i];
        }
        switch ( len )
        {
            case 1: *(uint8_t *)endianedp = (uint8_t)x; break;
            case 2: *(uint16_t *)endianedp = (uint16_t)x; break;
            case 4: *(uint32_t *)endianedp = (uint32_t)x; break;
            case 8: *(uint64_t *)endianedp = (uint64_t)x; break;
        }
    }
    else
    {
        x = 0;
        switch ( len )
        {
            case 1: x = *(uint8_t *)endianedp; break;
            case 2: x = *(uint16_t *)endianedp; break;
            case 4: x = *(uint32_t *)endianedp; break;
            case 8: x = *(uint64_t *)endianedp; break;
        }
        for (i=0; i<len; i++,x >>= 8)
            serialized[i] = (uint8_t)(x & 0xff);
    }
    return(len);
}

int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp)
{
    int32_t i;
    if ( rwflag == 0 )
    {
        for (i=0; i<len; i++)
            endianedp[i] = serialized[i];
    }
    else
    {
        for (i=0; i<len; i++)
            serialized[i] = endianedp[i];
    }
    return(len);
}


int32_t komodo_core::komodo_chainactive_timestamp()
{
   cryptonote::block b;
    if ( m_core.get_current_blockchain_height()-1 != 0 ) {
        cryptonote::block b = m_core.get_blockchain_storage().get_db().get_top_block();
        return(b.timestamp);
    }
    else return(0);
}

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
        else fprintf(stderr,"komodo_chainactive height %lu > active.%llu\n",height,tipheight);
    }
    fprintf(stderr,"komodo_chainactive null chainActive.Tip() height %lu\n",height);
    return false;
}

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

void komodo_importpubkeys()
{
    int32_t i,n,j,m,offset = 1,val,dispflag = 0; char *pubkey;

    n = (int32_t)(sizeof(Notaries_elected1)/sizeof(*Notaries_elected1));

    for (i=0; i<n; i++) // each year add new notaries too
    {
        if ( Notaries_elected1[i][offset] == 0 )
            continue;
        if ( (m= (int32_t)strlen((char *)Notaries_elected1[i][offset])) > 0 )
        {
	    pubkey = (char*) Notaries_elected1[i][offset];
	    //fprintf(stderr,"pubkey=%s\n", pubkey );

	    std::vector<unsigned char> vPubkey(pubkey, pubkey + m);
	    std::string addr = bytes256_to_hex(vPubkey);

	    //fprintf(stderr,"addr=%s\n", addr.c_str() );

 //           if ( (val= komodo_importaddress(addr)) < 0 )
 //               fprintf(stderr,"error importing (%s)\n",addr.c_str());
 //           else if ( val == 0 )
                dispflag++;
        }
    }
    if ( dispflag != 0 )
        fprintf(stderr,"%d Notary pubkeys imported\n",dispflag);
}

int32_t komodo_core::komodo_init()
{
    decode_hex(NOTARY_PUBKEY33,33,(char *)NOTARY_PUBKEY.c_str());
    return(0);
}

komodo_core* m_komodo_core;

komodo_core& get_k_core()
{
  return *m_komodo_core;
}

 bits256 iguana_merkle(bits256 *root_hash, int txn_count)
 {  // this function is incomplete and has been modified from the original
    // consult komodo_validation011.h for unmodified version

  int i,n=0,prev; uint8_t serialized[sizeof(crypto::hash) * 2];
   // crypto::hash tree_hash = cryptonote::get_tx_tree_hash(b.tx_hashes);
    bits256 *tree = nullptr;
    memcpy(&tree,&root_hash,sizeof(root_hash));

    if ( txn_count == 1 )
        return(tree[0]);
    prev = 0;
    while ( txn_count > 1 )
    {
        if ( (txn_count & 1) != 0 )
            tree[prev + txn_count] = tree[prev + txn_count-1], txn_count++;
        n += txn_count;
        for (i=0; i<txn_count; i+=2)
        {
            iguana_rwbignum(1,serialized,sizeof(*tree),tree[prev + i].bytes);
            iguana_rwbignum(1,&serialized[sizeof(*tree)],sizeof(*tree),tree[prev + i + 1].bytes);
            tree[n + (i >> 1)] = bits256_doublesha256(0,serialized,sizeof(serialized));
        }
        prev = n;
        txn_count >>= 1;
    }
    return(tree[n]);
}

int32_t komodo_core::komodo_notaries(uint8_t pubkeys[64][33],uint64_t height,uint64_t timestamp)
{
    static uint8_t elected_pubkeys0[64][33],elected_pubkeys1[64][33],did0,did1; static int32_t n0,n1;
    int32_t i;
    if ( timestamp == 0 && ASSETCHAINS_SYMBOL[0] != 0 )
        timestamp = komodo_heightstamp(height);
    else if ( ASSETCHAINS_SYMBOL[0] == 0 )
        timestamp = 0;
    if ( ASSETCHAINS_SYMBOL[0] != 0 )
    {
        if ( (timestamp != 0 && timestamp <= KOMODO_NOTARIES_TIMESTAMP1) || (ASSETCHAINS_SYMBOL[0] == 0 && height <= KOMODO_NOTARIES_HEIGHT1) )
        {
            if ( did0 == 0 )
            {
                n0 = (int32_t)(sizeof(Notaries_elected0)/sizeof(*Notaries_elected0));
                for (i=0; i<n0; i++)
                    decode_hex(elected_pubkeys0[i],33,(char *)Notaries_elected0[i][1]);
                did0 = 1;
            }
            memcpy(pubkeys,elected_pubkeys0,n0 * 33);
            if ( ASSETCHAINS_SYMBOL[0] != 0 )
              fprintf(stderr,"%s height.%lu t.%lu elected.%d notaries\n",ASSETCHAINS_SYMBOL,height,timestamp,n0);
            return(n0);
        }
        else //if ( (timestamp != 0 && timestamp <= KOMODO_NOTARIES_TIMESTAMP2) || height <= KOMODO_NOTARIES_HEIGHT2 )
        {
            if ( did1 == 0 )
            {
                n1 = (int32_t)(sizeof(Notaries_elected1)/sizeof(*Notaries_elected1));
                for (i=0; i<n1; i++)
                    decode_hex(elected_pubkeys1[i],33,(char *)Notaries_elected1[i][1]);
                if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                    fprintf(stderr,"%s height.%lu t.%lu elected.%d notaries2\n",ASSETCHAINS_SYMBOL,height,timestamp,n1);
                did1 = 1;
            }
            memcpy(pubkeys,elected_pubkeys1,n1 * 33);
            return(n1);
        }
    }
    return(-1);
}

void komodo_clearstate()
{
    portable_mutex_lock(&komodo_mutex);
    memset(&NOTARIZED_HEIGHT,0,sizeof(NOTARIZED_HEIGHT));
    std::fill(NOTARIZED_HASH.begin(),NOTARIZED_HASH.begin()+32,0);
    std::fill(NOTARIZED_DESTTXID.begin(),NOTARIZED_DESTTXID.begin()+32,0);
    std::fill(NOTARIZED_MOM.begin(),NOTARIZED_MOM.begin()+32,0);
    memset(&NOTARIZED_MOMDEPTH,0,sizeof(NOTARIZED_MOMDEPTH));
    memset(&last_NPOINTSi,0,sizeof(last_NPOINTSi));
    portable_mutex_unlock(&komodo_mutex);
}


void komodo_core::komodo_disconnect(uint64_t height,cryptonote::block block)
{
    if ( height <= NOTARIZED_HEIGHT )
    {
//        uint64_t block_height = m_core.get_blockchain_storage().get_db().get_block_id_by_height(block);
        uint64_t block_height = height;
        fprintf(stderr,"komodo_disconnect unexpected reorg at height = %llu vs NOTARIZED_HEIGHT = %d\n",block_height,NOTARIZED_HEIGHT);
        komodo_clearstate(); // bruteforce shortcut. on any reorg, no active notarization until next one is seen
    }
}


struct notarized_checkpoint
{
    uint256 notarized_hash,notarized_desttxid,MoM,MoMoM;
    int32_t nHeight,notarized_height,MoMdepth,MoMoMdepth,MoMoMoffset,kmdstarti,kmdendi;
} *NPOINTS;

int32_t komodo_prevMoMheight()
{
    static uint256 zero;
    int32_t i; struct notarized_checkpoint *np = 0;
    for (i=NUM_NPOINTS-1; i>=0; i--)
    {
        np = &NPOINTS[i];
        if ( np->MoM != zero )
            return(np->notarized_height);
    }
    return(0);
}

//struct komodo_state *komodo_stateptr(char *symbol,char *dest);
int32_t komodo_notarized_height(uint64_t *prevMoMheightp, uint256 *hashp,uint256 *txidp)
{
    *hashp = NOTARIZED_HASH;
    *txidp = NOTARIZED_DESTTXID;
    *prevMoMheightp = komodo_prevMoMheight();
    return(NOTARIZED_HEIGHT);
}

struct notarized_checkpoint *komodo_npptr(uint64_t height)
{
    int i; struct notarized_checkpoint *np = 0;
    for (i=NUM_NPOINTS-1; i>=0; i--)
    {
        np = &NPOINTS[i];
        if ( np->MoMdepth > 0 &&  height > np->notarized_height-np->MoMdepth && height <= np->notarized_height )
            return(np);
    }
    return(0);
}

int32_t komodo_core::komodo_notarizeddata(uint64_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp)
{
    struct notarized_checkpoint *np = 0; int32_t i=0,flag = 0;
    if ( NUM_NPOINTS > 0 )
    {
        flag = 0;
        if ( last_NPOINTSi < NUM_NPOINTS && last_NPOINTSi > 0 )
        {
            np = &NPOINTS[last_NPOINTSi-1];
            if ( np->nHeight < nHeight )
            {
                for (i=last_NPOINTSi; i<NUM_NPOINTS; i++)
                {
                    if ( NPOINTS[i].nHeight >= nHeight )
                    {
                        printf("flag.1 i.%d np->ht %d [%d].ht %d >= nHeight.%llu, last.%d num.%d\n",i,np->nHeight,i,NPOINTS[i].nHeight,nHeight,last_NPOINTSi,NUM_NPOINTS);
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
                if ( NPOINTS[i].nHeight >= nHeight )
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
        if ( np->nHeight >= nHeight || (i < NUM_NPOINTS && np[1].nHeight < nHeight) )
            fprintf(stderr,"warning: flag.%d i.%d np->ht %d [1].ht %d >= nHeight.%llu\n",flag,i,np->nHeight,np[1].nHeight,nHeight);
        *notarized_hashp = np->notarized_hash;
        *notarized_desttxidp = np->notarized_desttxid;
        return(np->notarized_height);
    }
    std::fill(notarized_hashp->begin(),notarized_hashp->begin()+32,0);
    std::fill(notarized_desttxidp->begin(),notarized_desttxidp->begin()+32,0);
    return(0);
}

void komodo_core::komodo_notarized_update(uint64_t nHeight,uint64_t notarized_height,uint256 notarized_hash,uint256 notarized_desttxid,uint256 MoM,int32_t MoMdepth)
{
    static int didinit; static uint256 zero; static FILE *fp; cryptonote::block *pindex = nullptr; struct notarized_checkpoint *np,N; long fpos;
    if ( didinit == 0 )
    {
        char fname[512]; uint64_t latestht = 0;
        decode_hex(NOTARY_PUBKEY33,33,(char *)NOTARY_PUBKEY.c_str());
        pthread_mutex_init(&komodo_mutex,NULL);
//#ifdef _WIN32
//        sprintf(fname,"%s\\notarizations",GetDefaultDataDir().string().c_str());
//#else
//        sprintf(fname,"%s/notarizations",GetDefaultDataDir().string().c_str());
//#endif
//       printf("fname.(%s)\n",fname);
        if ( (fp= fopen(fname,"rb+")) == 0 )
            fp = fopen(fname,"wb+");
        else
        {
            fpos = 0;
            while ( fread(&N,1,sizeof(N),fp) == sizeof(N) )
            {
                //pindex = komodo_chainactive(N.notarized_height);
                //if ( pindex != 0 && pindex->GetBlockHash() == N.notarized_hash && N.notarized_height > latestht )
                if ( N.notarized_height > latestht )
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
        fprintf(stderr,"komodo_notarized_update REJECT notarized_height %llu > %llu nHeight\n",notarized_height,nHeight);
        return;
    }

    bool active = komodo_chainactive(notarized_height, *pindex);
//    crypto::hash db_hash = m_core.get_block_hash_from_height(m_core.height());
//    uint256 hash;
//    std::vector<unsigned char> db_v = hex_to_bytes256(epee::string_tools::pod_to_hex(db_hash));
    if ( (!active) || notarized_height >= (m_core.get_blockchain_storage().get_db().height()-1) )
    {
//        crypto::hash index_hash = m_core.get_blockchain_storage().get_db().get_block_hash(pindex);
        uint64_t index_height = cryptonote::get_block_height(*pindex);
        fprintf(stderr,"komodo_notarized_update reject nHeight.%llu notarized_height.%llu:%llu\n",nHeight,notarized_height, index_height);
        return;
    }
    fprintf(stderr,"komodo_notarized_update nHeight.%llu notarized_height.%llu prev.%d\n",nHeight,notarized_height,NPOINTS!=0?NPOINTS[NUM_NPOINTS-1].notarized_height:-1);
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

int32_t komodo_core::komodo_checkpoint(int32_t *notarized_heightp, uint64_t nHeight, crypto::hash& hash)
{

    int32_t notarized_height; std::vector<uint8_t> zero;uint256 notarized_hash,notarized_desttxid; uint64_t notary; cryptonote::block *pindex = nullptr;
    std::fill(zero.begin(),zero.begin()+32,0);
    //komodo_notarized_update(0,0,zero,zero,zero,0);
    uint64_t activeheight = m_core.get_blockchain_storage().get_db().height()-1;
    bool active = komodo_chainactive(activeheight, *pindex);
    std::vector<uint8_t> v_nhash(notarized_hash.begin(), notarized_hash.begin()+32);
    std::string s_notarized_hash = bytes256_to_hex(v_nhash);
    if (!active)
        return(-1);
    notarized_height = komodo_notarizeddata(m_core.get_blockchain_storage().get_db().height(),&notarized_hash,&notarized_desttxid);
    *notarized_heightp = notarized_height;
    if ( notarized_height >= 0 && notarized_height <= activeheight && (notary= m_core.get_blockchain_storage().get_db().get_block_height(hash) != 0 ))
    {
        printf("activeheight.%llu -> (%d %s)\n",activeheight,notarized_height,s_notarized_hash.c_str());
        if ( notary == notarized_height ) // if notarized_hash not in chain, reorg
        {
            if ( activeheight < notarized_height )
            {
                fprintf(stderr,"activeheight.%llu < NOTARIZED_HEIGHT.%d\n",activeheight,notarized_height);
                return(-1);
            }
            else if ( activeheight == notarized_height && memcmp(&hash,&notarized_hash,sizeof(hash)) != 0 )
            {
                fprintf(stderr,"nHeight.%llu == NOTARIZED_HEIGHT.%d, diff hash\n",activeheight,notarized_height);
                return(-1);
            }
        } else fprintf(stderr,"unexpected error notary_hash %s ht.%d at ht.%llu\n",s_notarized_hash.c_str(),notarized_height,notary);
    } else if ( notarized_height > 0 )
        fprintf(stderr,"%s couldnt find notarized.(%s %d) ht.%d\n",ASSETCHAINS_SYMBOL,s_notarized_hash.c_str(),notarized_height,pindex);
    return(0);
}

/*
void komodo_voutupdate(int32_t txi,int32_t vout,uint8_t *scriptbuf,int32_t scriptlen,int32_t height,int32_t *specialtxp,int32_t *notarizedheightp,uint64_t value,int32_t notarized,uint64_t signedmask)
{

    static uint256 zero; static uint8_t crypto777[33];
    int32_t MoMdepth,opretlen,len = 0; uint256 hash,desttxid,MoM;
    if ( scriptlen == 35 && scriptbuf[0] == 33 && scriptbuf[34] == 0xac )
    {
        if ( crypto777[0] != 0x02 )// && crypto777[0] != 0x03 )
            decode_hex(crypto777,33,(char *)CRYPTO777_PUBSECPSTR);
        if ( memcmp(crypto777,scriptbuf+1,33) == 0 )
            *specialtxp = 1;
    }
    if ( scriptbuf[len++] == 0x6a )
    {
        if ( (opretlen= scriptbuf[len++]) == 0x4c )
            opretlen = scriptbuf[len++]; // len is 3 here
        else if ( opretlen == 0x4d )
        {
            opretlen = scriptbuf[len++];
            opretlen += (scriptbuf[len++] << 8);
        }
        //printf("opretlen.%d vout.%d [%s].(%s)\n",opretlen,vout,(char *)&scriptbuf[len+32*2+4],ASSETCHAINS_SYMBOL);
        if ( vout == 1 && opretlen-3 >= 32*2+4 && strcmp(ASSETCHAINS_SYMBOL,(char *)&scriptbuf[len+32*2+4]) == 0 )
        {
            len += iguana_rwbignum(0,&scriptbuf[len],32,(uint8_t *)&hash);
            len += iguana_rwnum(0,&scriptbuf[len],sizeof(*notarizedheightp),(uint8_t *)notarizedheightp);
            len += iguana_rwbignum(0,&scriptbuf[len],32,(uint8_t *)&desttxid);
            if ( notarized != 0 && *notarizedheightp > NOTARIZED_HEIGHT && *notarizedheightp < height )
            {
                int32_t nameoffset = (int32_t)strlen(ASSETCHAINS_SYMBOL) + 1;
                //NOTARIZED_HEIGHT = *notarizedheightp;
                //NOTARIZED_HASH = hash;
                //NOTARIZED_DESTTXID = desttxid;
                memset(&MoM,0,sizeof(MoM));
                MoMdepth = 0;
                len += nameoffset;
                if ( len+36-3 <= opretlen )
                {
                    len += iguana_rwbignum(0,&scriptbuf[len],32,(uint8_t *)&MoM);
                    len += iguana_rwnum(0,&scriptbuf[len],sizeof(MoMdepth),(uint8_t *)&MoMdepth);
                    if ( MoM == zero || MoMdepth > *notarizedheightp || MoMdepth < 0 )
                    {
                        memset(&MoM,0,sizeof(MoM));
                        MoMdepth = 0;
                    }
                    else
                    {
                        fprintf(stderr,"VALID %s MoM.%s [%d]\n",ASSETCHAINS_SYMBOL,MoM.ToString().c_str(),MoMdepth);
                    }
                }
                komodo_notarized_update(height,*notarizedheightp,hash,desttxid,MoM,MoMdepth);
                fprintf(stderr,"%s ht.%d NOTARIZED.%d %s %sTXID.%s lens.(%d %d)\n",ASSETCHAINS_SYMBOL,height,*notarizedheightp,hash.ToString().c_str(),"KMD",desttxid.ToString().c_str(),opretlen,len);
            } else fprintf(stderr,"notarized.%d ht %d vs prev %d vs height.%d\n",notarized,*notarizedheightp,NOTARIZED_HEIGHT,height);
        }
    }
}
*/


void komodo_core::komodo_connectblock(uint64_t& height,cryptonote::block& b)
{
    static uint64_t hwmheight;
    uint64_t signedmask; uint8_t scriptbuf[4096],pubkeys[64][33],scriptPubKey[35]; crypto::hash zero; int i,j,k,/*numnotaries,*/notarized,scriptlen,numvalid,specialtx,notarizedheight,len,numvouts,numvins;
    size_t txn_count = 0;

    uint64_t nHeight = height;

    if ( KOMODO_NEEDPUBKEYS != 0 )
    {
        komodo_importpubkeys();
        KOMODO_NEEDPUBKEYS = 0;
    }
    memset(&zero,0,sizeof(zero));
//    komodo_notarized_update(0,0,zero,zero,zero,0);
/*    numnotaries = komodo_notaries(pubkeys, nHeight, b.timestamp);*/

    if ( nHeight > hwmheight )
        hwmheight = nHeight;
    else
    {
        if ( nHeight != hwmheight )
            printf("dpow: %s hwmheight.%llu vs pindex->nHeight.%llu t.%llu reorg.%llu\n",ASSETCHAINS_SYMBOL,hwmheight,nHeight,b.timestamp,hwmheight - nHeight);
    }
/*
    if ( height != 0 )
    {
        height = nHeight;
        std::vector<cryptonote::transaction> txs = b.tx_hashes;
        size_t txn_counter;
        for (const auto& tx : txs) {
          ++txn_counter;
        }
        txn_count = tx_counter;
        //fprintf(stderr, "txn_count=%d\n", txn_count);
        for (i=0; i<txn_count; i++)
        {
            //txhash = block.vtx[i]->GetHash();
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
*/
  }

int32_t komodo_init()
{
  komodo_core& k_core = get_k_core();
  return k_core.komodo_init();
}


int32_t komodo_MoMdata(int32_t *notarized_htp,uint256 *MoMp,uint256 *kmdtxidp,int32_t height,uint256 *MoMoMp, int32_t *MoMoMoffsetp, int32_t *MoMoMdepthp, int32_t *kmdstartip, int32_t *kmdendip)
{
    struct notarized_checkpoint *np = 0;
    if ( (np= komodo_npptr(height)) != 0 )
    {
        *notarized_htp = np->notarized_height;
//        memcpy(*MoMp,np->MoM,32);
//        memcpy(*kmdtxidp,np->notarized_desttxid,32);
//        memcpy(*MoMoMp,np->MoMoM,32);
        *MoMp = np->MoM;
        *kmdtxidp = np->notarized_desttxid;
        *MoMoMp = np->MoMoM;
        *MoMoMoffsetp = np->MoMoMoffset;
        *MoMoMdepthp = np->MoMoMdepth;
        *kmdstartip = np->kmdstarti;
        *kmdendip = np->kmdendi;
        return(np->MoMdepth);
    }
    *notarized_htp = *MoMoMoffsetp = *MoMoMdepthp = *kmdstartip = *kmdendip = 0;
    std::fill(MoMp->begin(),MoMp->begin()+32,0);
    std::fill(MoMoMp->begin(),MoMoMp->begin()+32,0);
    std::fill(kmdtxidp->begin(),kmdtxidp->begin()+32,0);
    return(0);
}


/*int32_t komodo_MoM(int32_t *notarized_heightp,uint256 *MoMp,uint256 *kmdtxidp,int32_t nHeight,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *kmdstartip,int32_t *kmdendip)
{
    int32_t depth;
    int32_t notarized_ht;
    uint256 MoM;
    uint256 kmdtxid;

    std::vector<uint8_t> v_MoM(MoM.begin(), MoM.begin() + 32);
    std::vector<uint8_t> v_kmdtxid(kmdtxid.begin(), kmdtxid.begin() + 32);

    depth = komodo_MoMdata(&notarized_ht,&MoM,&kmdtxid,nHeight,MoMoMp,MoMoMoffsetp,MoMoMdepthp,kmdstartip,kmdendip);
    std::fill(v_MoM.begin(), v_MoM.begin()+32, 0);
    std::fill(v_kmdtxid.begin(), v_kmdtxid.begin()+32, 0);
    *notarized_heightp = 0;
    if ( depth > 0 && notarized_ht > 0 && nHeight > notarized_ht-depth && nHeight <= notarized_ht )
    {
        *MoMp = MoM;
        *notarized_heightp = notarized_ht;
        *kmdtxidp = kmdtxid;
    }
    return(depth);
}
*/

} // namespace komodo

} // namespace cryptonote
