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

#ifndef komodo_rpcblockchain_h
#define komodo_rpcblockchain_h

#pragma once

#include "libbtc/include/btc/btc.h"

namespace cryptonote {
namespace komodo {

struct notarized_checkpoint
{
    uint256 notarized_hash,notarized_desttxid,MoM,MoMoM;
    int32_t nHeight,notarized_height,MoMdepth,MoMoMdepth,MoMoMoffset,kmdstarti,kmdendi;
} *NPOINTS;

int32_t NUM_NPOINTS,last_NPOINTSi,NOTARIZED_HEIGHT,NOTARIZED_MOMDEPTH,KOMODO_NEEDPUBKEYS;
uint256 NOTARIZED_HASH, NOTARIZED_MOM, NOTARIZED_DESTTXID;


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

} // namespace komodo
} // namespace cryptonote
#endif /* komodo_rpcblockchain_h */

