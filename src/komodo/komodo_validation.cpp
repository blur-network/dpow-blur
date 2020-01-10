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
 * Parts of this file have been modified for compatibility with the Blur Nework.
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

#include "komodo_validation.h"
#include "common/hex_str.h"
#include "crypto/crypto.h"
#include "p2p/net_node.h"
#include "crypto/hash-ops.h"
#include "p2p/net_node.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/komodo_notaries.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_core/komodo_notaries.h"
#include "komodo_notary_server/notary_server.h"
#include "bitcoin/bitcoin.h"
#include "libbtc/include/btc/btc.h"
#include "libbtc/include/tool.h"
#include "libbtc/src/secp256k1/include/secp256k1.h"
#include <limits.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "libhydrogen/hydrogen.h"

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

  void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len)
  {
    struct sha256_vstate md;
    sha256_vinit(&md);
    sha256_vprocess(&md,src,len);
    sha256_vdone(&md,hash);
  }
  //------------------------------------------------------------------
  bits256 bits256_doublesha256(char *deprecated,uint8_t *data,int32_t datalen)
  {
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(0,hash.bytes,data,datalen);
    vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<(int32_t)sizeof(hash); i++)
      hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    return(hash);
  }
  //------------------------------------------------------------------
  int32_t bitweight(uint64_t x)
  {
    int i,wt = 0;
    for (i=0; i<64; i++)
      if ( (1LL << i) & x )
        wt++;
    return(wt);
  }
  //------------------------------------------------------------------
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
  //------------------------------------------------------------------
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
  //------------------------------------------------------------------
  int32_t unhex(char c)
  {
    int32_t hex;
    if ( (hex= _unhex(c)) < 0 )
    {
      //printf("unhex: illegal hexchar.(%c)\n",c);
    }
    return(hex);
  }
  //------------------------------------------------------------------
  unsigned char _decode_hex(char *hex) { return((unhex(hex[0])<<4) | unhex(hex[1])); }
  //------------------------------------------------------------------
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
  //------------------------------------------------------------------
  char hexbyte(int32_t c)
  {
    c &= 0xf;
    if ( c < 10 )
      return('0'+c);
    else if ( c < 16 )
      return('a'+c-10);
    else return(0);
  }
  //------------------------------------------------------------------
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
  //------------------------------------------------------------------
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
  //------------------------------------------------------------------
  bits256 iguana_merkle(bits256 *tree, int& txn_count)
  {
    int i,n=0,prev; uint8_t serialized[sizeof(bits256) * 2];
    if ( txn_count == 1 )
    {
//      iguana_rwbignum(1,serialized,sizeof(*tree),tree[0].bytes);
//      iguana_rwbignum(1,&serialized[sizeof(*tree)],sizeof(*tree),tree[1].bytes);
      tree[0] = bits256_doublesha256(0, serialized, sizeof(serialized));
      MWARNING("Tree[0] bits256_doublesha:     " << std::to_string(tree->txid));
      return(tree[0]);
    }
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
    MWARNING("Tree[n] bits256_doublesha:     " << std::to_string(tree->txid));
    return(tree[n]);
  }
} // namespace komodo

} // namespace cryptonote
