extern "C" {

#pragma once

#pragma pack(push, 1)
struct output_data_t
{
  crypto::public_key pubkey;
  uint64_t           unlock_time;
  uint64_t           height;
  rct::key           commitment;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct tx_data_t
{
  uint64_t tx_id;
  uint64_t unlock_time;
  uint64_t block_id;
};
#pragma pack(pop)

namespace cryptonote {

typedef struct mdb_block_info
{
  uint64_t bi_height;
  uint64_t bi_timestamp;
  uint64_t bi_coins;
  uint64_t bi_size; // a size_t really but we need 32-bit compat
  difficulty_type bi_diff;
  crypto::hash bi_hash;
} mdb_block_info;

typedef struct blk_height {
    crypto::hash bh_hash;
    uint64_t bh_height;
} blk_height;

typedef struct txindex {
    crypto::hash key;
    tx_data_t data;
} txindex;

typedef struct ntzindex {
    crypto::hash key;
    uint64_t ntz_id;
    uint64_t ntz_height;
} ntzindex;

typedef struct outkey {
    uint64_t amount_index;
    uint64_t output_id;
    output_data_t data;
} outkey;

typedef struct outtx {
    uint64_t output_id;
    crypto::hash tx_hash;
    uint64_t local_index;
} outtx;

} //namespace cryptonote

}
