# This repository is under contruction

There are files in here from many different projects, including but not limited to XMR, BTC, BLUR, and KMD. Please retain proper licensing if you reuse any files, and be aware that this repo is under heavy development... So files will not yet be in their proper homes.

# Creating a Notarization Wallet for Notarization Tx's on BLUR

**To create a wallet on BLUR's network, for notary nodes already owning a secp256k1 private key:**
*Note: Password prompt is not yet working*

Compile binaries from source, then create a json-formatted wallet configuration file formatted as follows: 
(named `btc.json` in our example)


```
{
        "version": 1,
        "filename": "muh_wallet",
        "scan_from_height": 0,
        "btc_pubkey":"24e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842"
}
```


Substitute the hexidecimal representation of your node's public key into the field titled `btc_pubkey`.


Then, launch the `blur-notary-server-rpc` with the following options (change the name of the json file if you named yours something other than `btc.json`): 


```
./blur-notary-server-rpc --generate-from-btc-pubkey btc.json --rpc-bind-port 11111 --prompt-for-password
```


You should see the following:


![nnwallet](https://i.imgur.com/I9cRpQp.png)


Double check that the values in red match each other! If they do not, then the wallet was generated incorrectly, or data was corrupted between generation, and a check on the values afterward. 
# RPC Calls for KMD-BLUR Data

**To retrieve the current blockchain data, and notarization data (not yet populated):**

`curl -X POST http://localhost:52542/json_rpc -d '{"method":"get_notarization_data"}'`

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
To retrieve the merkle root of a given block, by block hash or by vector of transaction hashes (`b.miner_tx` + `b.tx_hashes`):

By block hash:
```
$ curl -X POST http://localhost:52542/json_rpc -d '{"method":"get_merkle_root","params":{"block_hash":"fcef71dbd8138c1bb738df9848307bd766af11e763c9125014a023db706877d"}}'
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "status": "OK",
    "tree_hash": "8f85f91445345bfdc47633fb8f81002781994ace103706568f97249e5f5efee1"
  }
}
```
By transaction hashes:
```
$ curl -X POST http://localhost:52542/json_rpc -d '{"method":"get_merkle_root","params":{"tx_hashes":["6ca1743cb1db1f4f34b132919b7941f766146b4dbf36fd6db88ff9563b7710b","abdbab0a70288fc8106de68715db988e901cf51f77696011c6479822a9236b8b"]}}'
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "status": "OK",
    "tree_hash": "8f85f91445345bfdc47633fb8f81002781994ace103706568f97249e5f5efee1"
```
