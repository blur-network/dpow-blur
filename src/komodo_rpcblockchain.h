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


int32_t komodo_MoMdata(int32_t *notarized_htp,uint256 *MoMp,uint256 *kmdtxidp,int32_t height,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *kmdstartip,int32_t *kmdendip);
uint256 komodo_calcMoM(int32_t height,int32_t MoMdepth);
extern char ASSETCHAINS_SYMBOL[65];



int32_t komodo_MoM(int32_t *notarized_heightp,uint256 *MoMp,uint256 *kmdtxidp,int32_t nHeight,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *kmdstartip,int32_t *kmdendip)
{
    int32_t depth;
    int32_t notarized_ht;
    uint256 MoM;
    uint256 kmdtxid;

    //arith_uint256 v_MoM = UintToArith256(MoM);
    //std::vector<uint8_t> v_MoM(MoM.begin(), MoM.begin() + 32);
    //arith_uint256 v_kmdtxid = UintToArith256(kmdtxid);
    //std::vector<uint8_t> v_kmdtxid(kmdtxid.begin(), kmdtxid.begin() + 32);

    depth = komodo_MoMdata(&notarized_ht,&MoM,&kmdtxid,nHeight,MoMoMp,MoMoMoffsetp,MoMoMdepthp,kmdstartip,kmdendip);
//    std::fill(v_MoM.begin(), v_MoM.begin()+32, 0);
    memset(MoMp, 0, sizeof(*MoMp));
//    std::fill(v_kmdtxid.begin(), v_kmdtxid.begin()+32, 0);
    memset(kmdtxidp, 0, sizeof(*kmdtxidp));
    *notarized_heightp = 0;
    if ( depth > 0 && notarized_ht > 0 && nHeight > notarized_ht-depth && nHeight <= notarized_ht )
    {
        *MoMp = MoM;
        *notarized_heightp = notarized_ht;
        *kmdtxidp = kmdtxid;
    }
    return(depth);
}


#endif /* komodo_rpcblockchain_h */

