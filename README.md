# This repository is under contruction

There are files in here from many different projects, including but not limited to XMR, BTC, BLUR, and KMD. Please retain proper licensing if you reuse any files, and be aware that this repo is under heavy development... So files will not yet be in their proper homes.

# Contents:
- <a href="https://github.com/blur-network/dpow-blur#deps">Dependencies</a>
- <a href="https://github.com/blur-network/dpow-blur#create-wallet">Create a notary wallet</a>
- <a href="https://github.com/blur-network/dpow-blur#start-wallet">Launching a notary wallet</a>
- <a href="https://github.com/blur-network/dpow-blur#create-tx">Create a notarization tx</a>
- <a href="https://github.com/blur-network/dpow-blur#relay-tx">Relaying a notarization tx</a>
- <a href="https://github.com/blur-network/dpow-blur#view-pending">Viewing pending notarization txs</a>
- <a href="https://github.com/blur-network/dpow-blur#rpc-calls">Other RPC calls</a>


<h2 id="deps"> Dependencies </h2>

Libhydrogen requires CMake 3.14+ to compile.  If your distribution does not include this in the package manager, you can download the latest release's source from here: <a href="https://github.com/Kitware/CMake/releases/download/v3.15.2/cmake-3.15.2.tar.gz">CMake 3.15.2 from Kitware's github</a>

Both libbtc and the native blur files require GCC 8.3 or below to compile.  GCC 9+ will error out.

Once that is extracted from the archive, building and installing is as simple as `./configure && make && sudo make install`

Ubuntu/Debian One-Liner:

`sudo apt install build-essential cmake pkg-config libssl-dev libunwind-dev libevent-dev libsodium-dev binutils-dev libboost-all-dev`

Arch Linux One-Liner: 

`sudo pacman -S base-devel cmake boost openssl libsodium libunwind binutils-devel libevent`

Fedora One-Liner: 

`sudo dnf install cmake boost-devel openssl-devel sodium-devel libunwind-devel binutils-devel libevent-devel`

<h2 id="create-wallet"> Creating a Notarization Wallet for Notarization Tx's on BLUR</h2>

*To create a wallet on BLUR's network, for notary nodes already owning a secp256k1 private key:*


**Step 1:** Compile binaries from source, then create a json-formatted wallet configuration file as follows: 
(named `btc.json` in our example)


```
{
        "version": 1,
        "filename": "test_wallet",
        "scan_from_height": 0,
        "btc_pubkey":"24e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842",
        "password":"password"
}
```

Substitute the hexidecimal representation of your node's public key into the field titled `btc_pubkey`.

**Step 2:** Launch `blurd` with the following options:


```
./blurd --testnet
```


**Step 3:** Launch `blur-notary-server-rpc` with the following options:

*Note: Change the name of the json file if you named yours something other than* `btc.json`


```
./blur-notary-server-rpc --generate-from-btc-pubkey btc.json --rpc-bind-port 12121 --testnet
```

You should see the following:

![nnwallet](https://i.imgur.com/I9cRpQp.png)


Double check that the values in red match each other! If they do not, then the wallet was generated incorrectly, or data was corrupted between generation, and a check on the values afterward. 

Your wallet should now be running.  Skip the `Starting the Notary Server Wallet` heading if you don't plan to shut down your notary node between this point and testing.

<br></br>

<h2 id="start-wallet">Starting the Notary Server Wallet</h2>

**Step 1:**  Start `blurd` with the following options:


```
./blurd --testnet
```


After your wallet is generated, you can reopen this existing file with the following startup flags:


```
./blur-notary-server-rpc --wallet-file test_wallet --rpc-bind-port 12121 --prompt-for-password --testnet --disable-rpc-login
```


The RPC interface will prompt you for the wallet password.  Enter the password you entered into `btc.json` on creation.
<br></br>

<h2 id="create-tx">Creating a Notarization Transaction</h2>


**Step 1:** Before creating a transaction, you must paste the public spendkey that was generated when creating your wallet, into the 4th column in the `Notaries_elected1` table, located in `src/komodo/komodo_notaries.h`.  If your public spendkey is not located in this table, the wallet will not permit you to create a notarization tx. 

**Step 2:**  Compile source again, and start up the daemon with `./blurd --testnet`.

**Step 3:**  After the daemon is running, launch the notary wallet with `blur-notary-server-rpc --wallet-file=test_wallet.keys --rpc-bind-port 12121 --prompt-for-password --disable-rpc-login --testnet`

**Step 4:** Issue the following `curl` command in a separate terminal:


```
curl -X POST http://127.0.0.1:12121/json_rpc -d '{"method":"create_ntz_transfer"}'
```


*Notes:*

The command above will create a new notarization tx with one signature.

The first two times this command is called, the generated transactions will be added to a cache (`ntz_ptx_cache`). 

Once there are two `pending_tx`s in the cache, the third call will be relayed as a request for more signatures using `NOTIFY_REQUEST_NTZ_SIG`

**TL;DR: The above needs called three separate times before it will send the first request for more signatures.  This is to speed up the addition of new signatures to `pending_tx`s, when found in the ntzpool. Each call takes about 5-10 seconds to complete.**

Destinations for the transaction are automatically populated, using the BTC & CryptoNote pubkeys provided in `komodo_notaries.h`.  Each notary wallet is sent 0.00000001 BLUR.

<br></br>

<h2 id="relay-tx">Relaying a request for Notarization Signatures from other Notary Nodes:</h2>

*Note:  this should already have been done automatically, following a call to the command ntz_transfer! However, if you wish to test the functionality yourself, you may also call the method manually.*

To relay the created `tx_blob` from the previous command `ntz_transfer` issued to the wallet, perform the following:


**Step 1:** Using the `tx_blob` from terminal output (`STDOUT` printed in response to the previous `ntz_transfer` command), issue the following `curl` command to the daemon's port `21111` (not the wallet):


```
curl -X POST http://localhost:21111/json_rpc -d '{"method":"request_ntz_sig","params":{"tx_blob":"long hex here","sig_count":1,"signers_index:[51,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1],"payment_id":"0c9a0f1fc513e0aa5d70cccb0b00e9ff924ce9c4b0e2ec373060fbde1c5cc4e0"}}'
```

*Note once again: this command will not relay an actual transaction unless `sig_count` is greater than 13.*

A further check is performed that checks `sig_count` against a count of numbers in `signers_index` that are not `-1`.  If these numbers do not match, the transaction will be rejected. 


<br></br>


<h2 id="view-pending">Viewing Pending Notarization Requests for Signatures from other Notary Nodes:</h2>

To view pending notarization txs, which have requested further notarization signatures:

Issue the following command to the running daemon interface: `print_pool`

If a notarization is currently idling in the mempool, awaiting further signatures, they will show up under the heading `Pending Notarization Transactions: `

Example:

User input:
```
print_pool
```
Terminal output:
```
Pending Notarization Transactions: 
=======================================================
id: 3202e96a36d74d6fc9a16211859c1c241cd3bc3f07143f3fbd3b95f65529b977
sig_count: 1
signers_index:  51 -1 -1 -1 -1 -1 -1 -1 -1 -1 -1 -1 -1 
blob_size: 52736
fee: 0.019509880000
fee/byte: 0.000000369953
receive_time: 1569443965 (22 seconds ago)
relayed: no
do_not_relay: F
kept_by_block: F
double_spend_seen: F
max_used_block_height: 1341
max_used_block_id: 525af472e44ea82e6f6b39c25ebc5f83b3fc157a9541cdba18cbf32cd69cd43f
last_failed_height: 0
last_failed_id: 0000000000000000000000000000000000000000000000000000000000000000
```

`sig_count` is a count of signatures currently added to the transaction. `signers_index` is an array with 13 values, each of which corresponds to a Notary Node, and their row number in the hardcoded pubkeys (from the `NotariesElected1` table, located in `src/komodo/komodo_notaries.h`).  If the value is not a default `-1`, the number should correspond to a notary node that has already signed and appended their transactions to the pending request, in time-sequential
order.

Because these notarization transactions use a completely separate validation structure (located in `src/cryptonote_basic/verification_context.h`), they will not validate
as normal transactions until `sig_count` reaches a point of being greater than `13`.  At this point, the `ntz_tx_verification_context` will be converted to the standard
`tx_verification_context`, and relayed to the network as a normal transcation.  Prior to this point, the separate context will prevent a transaction from being treated as a normal transaction, or validated as such by other nodes.


<br></br>


<h2 id="rpc-calls"> RPC Calls for KMD-BLUR Data </h2>


To retrieve the current blockchain data, and notarization data (not yet populated):


`curl -X POST http://localhost:52542/json_rpc -d '{"method":"get_notarization_data"}'`


Output:


```
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "assetchains_symbol": "BLUR",
    "current_chain_hash": "0d6b7b0de6106877972fdafb806932cdd4c30dd007fc9510dfdec4db8b5ca69c",
    "current_chain_height": 155736,
    "current_chain_pow": "73ab840dcb63e247df9d98988a195b2ba17def30daa835073a8377be65010000",
    "notarized_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "notarized_height": 0,
    "notarized_txid": "0000000000000000000000000000000000000000000000000000000000000000"
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

