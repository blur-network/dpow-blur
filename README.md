# This repository is under contruction

There are files in here from many different projects, including but not limited to XMR, BTC, BLUR, and KMD. Please retain proper licensing if you reuse any files, and be aware that this repo is under heavy development... So files will not yet be in their proper homes.

# RPC Calls for KMD-BLUR Data

**To retrieve the current blockchain data, and notarization data (not yet populated):**

`curl -X POST http://localhost:52542/json_rpc -d '{"method":"notarization_data"}'`

Output:
```
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "assetchains_symbol": "BLUR",
    "current_chain_hash": "77ec04e3dfea902e3f222f6d85b9d63077051bf29b6a5b9f3aabc16141ca08d1",
    "current_chain_height": 513064,
    "current_chain_pow": "231f28c80737845b358217ff1d095de492f600aacd2b2367d8957be471000000",
    "notarized": 0,
    "notarized_MoM": "0000000000000000000000000000000000000000000000000000000000000000",
    "notarized_MoMdepth": 0,
    "notarized_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "notarized_txid": "0000000000000000000000000000000000000000000000000000000000000000",
    "prevMoMheight": 0
  }
```
