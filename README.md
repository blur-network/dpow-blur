# This repository is under contruction
  
![DPoW Testnet Branch](https://github.com/blur-network/dpow-blur/workflows/DPoW%20Testnet%20Branch/badge.svg?branch=testnet)
  
There are files in here from many different projects, including but not limited to BLUR, BTC, KMD, and XMR. Please retain proper licensing if you reuse any files, and be aware that this repo is under heavy development... So files will not yet be in their proper homes.

## Setup For Notary Nodes on BLUR

Notary nodes can follow the procedure <a href="https://github.com/blur-network/dpow-blur/tree/dpow/docs/Blur-NN-Setup.md">located here</a>, with the guidance of a KMD administrator, to set up notary wallets for BLUR.

### Modify Required Signatures in DPoW Blur-Side Checkpointing

Located in `src/cryptonote_config.h`, there is a pre-compile constant set for `DPOW_SIG_COUNT`...  Changing this value will change the required amount of signatures, before a notarization process is deemed complete.  Once this number of signatures is reached on a given notarization transaction, the validation structs are converted to those of a standard BLUR transaction, and will be sent to the network. 

Any value between `2` and `21` is valid for this constant (but above `21` will require further modifications to database due to size constraints).

# Contents:

- <a href="https://github.com/blur-network/dpow-blur#compile">Compile From Source with Dependencies</a>
- <a href="https://github.com/blur-network/dpow-blur#deps">Dependencies (Package Manager)</a>
- <a href="https://github.com/blur-network/dpow-blur#create-wallet">Create a notary wallet</a>
- <a href="https://github.com/blur-network/dpow-blur#start-wallet">Launching a notary wallet</a>


### Automatically performed operations:
- <a href="https://github.com/blur-network/dpow-blur#create-tx">Create a notarization tx</a>
- <a href="https://github.com/blur-network/dpow-blur#relay-tx">Relaying a notarization tx (request for futher signatures)</a>
- <a href="https://github.com/blur-network/dpow-blur#append-sig">Appending signatures to a pending notarization</a>


### Manually performed operations
- <a href="https://github.com/blur-network/dpow-blur#view-pending">Viewing pending notarization txs</a>
- <a href="https://github.com/blur-network/dpow-blur#rpc-calls">Other RPC calls</a>

---


<h2 id="compile"> Compile from Source and Chain-Build with Dependencies </h2>


Minimal Dependencies: `sudo apt-get install autotools-dev curl cmake build-essential libtool`

**The following will chain-build dependencies and then all binaries in source:** `make release-cross-linux-x86_64`


---


<h2 id="deps"> Dependencies </h2>

Ubuntu/Debian One-Liner:

`sudo apt install build-essential pkg-config libssl-dev libunwind-dev libevent-dev libsodium-dev binutils-dev libboost-all-dev autoconf libreadline-dev`

Arch Linux One-Liner:

`sudo pacman -S base-devel boost openssl libsodium libunwind binutils libevent autoconf readline`

Fedora One-Liner:

`sudo dnf install boost-devel openssl-devel sodium-devel libunwind-devel binutils-devel libevent-devel autoconf readline-devel`

After installing the dependencies, clone this repo with:

> `git clone https://github.com/blur-network/dpow-blur.git`

`cd` into the proper directory, and then compile with:

`cd dpow-blur && git submodule update --init && make release-static`


---


<h2 id="create-wallet"> Creating a Notarization Wallet for Notarization Tx's on BLUR</h2>


**One may instead use the pre-generated wallets <a href="https://github.com/blur-network/dpow-blur/releases/tag/test-wallets">located here</a>, to use the testnet as a playground for notarizations. These wallets are pre-funded with BLUR.**


*To create a wallet on BLUR's network, for notary nodes already owning a secp256k1 private key:*


**Step 1:** Compile binaries from source, then create a json-formatted wallet configuration file as follows: 
(named `btc.json` in our example)


```
{
        "version": 1,
        "filename": "test_wallet",
        "scan_from_height": 0,
        "btc_pubkey":"0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842",
        "password":"password"
}
```

Substitute the hexidecimal representation of your notary node's public key into the field titled `btc_pubkey`.

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

![](https://i.ibb.co/6Z8vdb7/nn-2.png)


Your wallet should now be running.  Skip the `Starting the Notary Server Wallet` heading if you don't plan to shut down your notary node between this point and testing.


---


<h2 id="start-wallet">Starting the Notary Server Wallet</h2>

**Step 1:**  Start `blurd` with the following options:


```
./blurd --testnet --detach
```


After your wallet is generated, you can reopen this existing file with the following startup flags:


```
./blur-notary-server-rpc --wallet-file test_wallet --rpc-bind-port 12121 --prompt-for-password --testnet --disable-rpc-login
```


The RPC interface will prompt you for the wallet password.  Enter the password you entered into `btc.json` on creation.


---


<h2 id="create-tx">Creating a Notarization Transaction</h2>


<h4>Please note: Everything after step 3 will be performed automatically (without any action on your part) after launching the notary server.</h4>


<i>What is shown below, excluding steps 1-3, is for informational purposes.  You should never need to call</i> `create_ntz_transfer` or `append_ntz_sig` <i>methods manually.</i>


**Step 1:** Before creating a transaction, you must paste the public spendkey that was generated when creating your wallet, into the 4th column in the `Notaries_elected1` table, located in `src/komodo/komodo_notaries.h`.  If your public spendkey is not located in this table, the wallet will not permit you to create a notarization tx. 

**Step 2:**  Compile source again, and start up the daemon with `./blurd --testnet`.

**Step 3:**  After the daemon is running, launch the notary wallet with `blur-notary-server-rpc --wallet-file=test_wallet.keys --rpc-bind-port 12121 --prompt-for-password --disable-rpc-login --testnet`

**Step 4:** Issue the following `curl` command in a separate terminal:


```
curl -X POST http://127.0.0.1:12121/json_rpc -d '{"method":"create_ntz_transfer"}'
```


*Notes:*

The command above will create a new notarization tx with one signature, back to the NN's own address (a churn).  Each transaction sent is 0.00000001 BLUR (+fees).


---


<h2 id="append-sig">Appending signatures to a pending notarization</h2>

**Note: This should be performed automatically, once a notarization sequence has already begun (Pending notarization is in pool already, with `sig_count == 1`)** 

If you wish to call it manually, use the syntax below:

```
curl -X POST http://127.0.0.1:12121/json_rpc -d '{"method":"append_ntz_sig"}'
```

This command will check the notarization pool for pending tx's, and fetch the one with the highest value in the `sig_count` field. This field's value should match the quantity of non-negative elements in the `signers_index` field.

The called function will return false for any keypair that is not hardcoded in `src/komodo/komodo_notaries.h`

This function will automatically pull in all necessary tx data, as well as cleaning all transactions from the ntzpool, **except two pending txs**.

**These two transactions are:**

**1.)** The transaction which has just been signed  
**2.)** The transaction itself, prior to signing.

#2 is left in pool in the event that after leaving the wallet side, the transaction becomes invalid.  This transaction will be cleaned after the next notary node appends its signatures.

Once your signatures have been addded, you will see the following message displayed from the RPC interface: 

```
   [RPC0]    WARN     wallet.wallet2    src/wallet/wallet2.cpp:5046    transaction <45f1e4c9c48da583e294d0fb5f225ee4c5999b7f3f067b2bb753100e31ced9b0> generated ok and sent to request ntz sigs, key_images: [<3d1bd440676b6a32cf1b6b7b21fb6b25ca13038a18f4456c7165cff91a66c5aa> ]

    [RPC0]    WARN     wallet.wallet2    src/wallet/wallet2.cpp:5052    Signatures added. 4 more needed. Relaying NOTIFY_REQUEST_NTZ_SIG <<45f1e4c9c48da583e294d0fb5f225ee4c5999b7f3f067b2bb753100e31ced9b0>>

Signatures count: 9, Commission: 0.058350240000
Balance: 400.000000000000
Unlocked: 400.000000000000
Please, wait for further signatures

    [RPC0]    WARN     notary_server.rpc    src/komodo_notary_server/notary_server.cpp:1534    Signatures < (DPOW_SIG_COUNT): [request_ntz_sig] sent with sig_count: 9, signers_index =  12 35 5 61 55 47 21 20 26 -1
```


---


<h2 id="relay-tx">Relaying a request for Notarization Signatures from other Notary Nodes:</h2>

**This will also be performed automatically, upon a successful call to either of the above RPC methods**

To relay the created `tx_blob` from the previous command `ntz_transfer` issued to the wallet, perform the following:


Using the `tx_blob` from terminal output, issue the following `curl` command to the daemon's port `21111` (not the wallet):


```
curl -X POST http://localhost:21111/json_rpc -d '{"method":"request_ntz_sig","params":{"tx_blob":"long hex here","sig_count":1,"signers_index:[51,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1],"payment_id":"0c9a0f1fc513e0aa5d70cccb0b00e9ff924ce9c4b0e2ec373060fbde1c5cc4e0"}}'
```

*This protocol command will not relay an actual transaction unless `sig_count` is at least equal to DPOW_SIG_COUNT.* 


---


<h2 id="view-pending">Viewing Pending Notarizations</h2>
To view pending notarization txs, which have requested further notarization signatures:

Issue the following command to the running daemon interface: `print_pool`

If a notarization is currently idling in the mempool, awaiting further signatures, they will show up under the heading `Pending Notarization Transactions: `

Example:

User input:

```
print_pool
```

Output of a pending ntz tx with 9 signatures:

```
Pending Notarization Transactions: 
=======================================================
id: d17476f2d859cc5e87fb372b48b48297ed8f9efdea307a357fc633279715efef
ptx_hash: 47e529efadeba129cc4269cd04c4403f8ac04478d68e4ce4b48b46a976a37f35
sig_count: 9
signers_index:  20 04 03 21 18 51 61 47 60 -1 
blob_size: 54355
fee: 0.100000000000
fee/byte: 0.000001839757
receive_time: 1585684867 (2 hours ago)
relayed: 1585684867 (2 hours ago)
has_ntz_data: T
do_not_relay: F
kept_by_block: F
double_spend_seen: F
max_used_block_height: 2918
max_used_block_id: b1f7d5d0af36311c52e9a432af87a1c60332b122daf83bf4b3e0b7d1f5f44a90
last_failed_height: 0
last_failed_id: 0000000000000000000000000000000000000000000000000000000000000000
```

**Notes on fields not present in a standard BLUR tx:** 

`ptx_hash` is the hash of a corresponding `ptx_blob` binary archive.  This archive contains all transaction data from the previous signer, for the next signer to add to their vectorized txs.  

`sig_count` is a count of signatures currently added to the transaction. 

`signers_index` is an array with `DPOW_SIG_COUNT` values, each of which corresponds to a Notary Node, and their row number in the hardcoded pubkeys.

`has_ntz_data` indicates whether or not the transaction has upstream (KMD/BTC) notarization data embedded in the `tx_extra` field of the BLUR transaction in question.

If a value in the `signers_index` field is not a default `-1`, the number should correspond to a notary node that has already signed and appended their transactions to the pending request. Indices are added in time-sequential order.

**Regarding Validation**: Because these notarization transactions use a completely separate validation structure (located in `src/cryptonote_basic/verification_context.h`), they will not validate
as normal transactions until `sig_count` reaches a point of being greater than or equal to `DPOW_SIG_COUNT`.

At that point, the `ntz_tx_verification_context` will be converted to the standard
`tx_verification_context`, and relayed to the network as a normal transcation.  Prior to this point, the separate context will prevent a pending notarization from being handled as a normal transaction, or validated as such by other nodes.


---


<h2 id="rpc-calls"> RPC Calls for KMD-BLUR Data </h2>



## Retrieving Current Blockchain Notarization Data
 

To retrieve the current blockchain data, and notarization data (not yet populated):
 

`curl -X POST http://localhost:21111/json_rpc -d '{"method":"get_notarization_data"}'`
 

Output:

```
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "assetchains_symbol": "BLUR",
    "current_chain_hash": "0873d25c15a0ec2e08af077113a939a07ee8d87caea3c13680d3ef18fcd0ba06",
    "current_chain_height": 2939,
    "current_chain_pow": "303e4e06828a4c8f20e5a56207f5c665013b0b2e2aeacc5099b930f3bf521901",
    "embedded_btc_hash": "313031a1ed2dbe12a20706dff48d3dffb0e39d15e3e4ff936d01f091fb3b8556",
    "notarizations_completed": 7,
    "notarizations_merkle": "92fbf297fb1ba553f37a9bcaab93ba34b3bb352ae99a190852804a21a7e4a343",
    "notarized_hash": "0873d25c15a0ec2e08af077113a939a07ee8d87caea3c13680d3ef18fcd0ba06",
    "notarized_height": 2923,
    "notarized_txid": "a85701183ace0baa3334c327ee3e871422615fa4f65e35df889ff4ad3aea4e13"
  }
}
```

Note: `embedded_btc_hash` is a hash of the KMD/BTC data found in the BLUR `tx_extra` field.  The embedded KMD/BTC transaction is hashed using `doublesha256`, to yield a bitcoin txid.

*One may cross-reference the above transaction hash <a href="https://learnmeabitcoin.com/explorer/transaction/313031a1ed2dbe12a20706dff48d3dffb0e39d15e3e4ff936d01f091fb3b8556">on a BTC blockchain explorer</a>.*

---

## Retrieving Merkle Data for a Given Block

To retrieve the merkle root of a given block, by block hash or by vector of transaction hashes (`b.miner_tx` + `b.tx_hashes`):


**By block hash:**

 
```
$ curl -X POST http://localhost:21111/json_rpc -d '{"method":"get_merkle_root","params":{"block_hash":"fcef71dbd8138c1bb738df9848307bd766af11e763c9125014a023db706877d"}}'
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "status": "OK",
    "tree_hash": "8f85f91445345bfdc47633fb8f81002781994ace103706568f97249e5f5efee1"
  }
}
```


**By transaction hashes:**


```
$ curl -X POST http://localhost:21111/json_rpc -d '{"method":"get_merkle_root","params":{"tx_hashes":["6ca1743cb1db1f4f34b132919b7941f766146b4dbf36fd6db88ff9563b7710b","abdbab0a70288fc8106de68715db988e901cf51f77696011c6479822a9236b8b"]}}'
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "status": "OK",
    "tree_hash": "8f85f91445345bfdc47633fb8f81002781994ace103706568f97249e5f5efee1"
  }
}
```


## Decoding `OP_RETURN` Data from KMD

Get raw transaction data from a BLUR->KMD notarization (KMD txid):

```
$ komodo-cli getrawtransaction 4e1314221fdf53205591134c38cebcf832073643dc393cc20552b6b4f9001796

0400008085202f8902b3135368a62b33fcc1dcdaa224e5b74468f256381e85839d91f56b34f32788bd3b00000049483045022100ac8f1a53f4cb1c2bb5651cea4a88d916c4ea650798c1e9beec631d9a4592d13d022057b581e122f2e26dfb516896b43741b61ce3d7896a0cd71c3467059632cc8af401ffffffffba006cc4a963a26c3af6a5eaeb0d865f45d4698ccee27a6e4551231e4c73f42355000000494830450221008ac71ce1959017a0946ba01e82677c8b7ef9d79821824d41fa6c4fdaa9b0886e022073939d695f863858c7fd15131c787e8eee3e417731eb5f20ea32fc1928986e7b01ffffffff0210270000000000002321020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9ac00000000000000002b6a29668bc765d66e2bda159248c9b531129d41e8ec96e033b0e505312002303f337e3a260100424c55520000000000000000000000000000000000000000
```

Decode raw transaction:

```
$ komodo-cli decoderawtransaction 0400008085202f8902b3135368a62b33fcc1dcdaa224e5b74468f256381e85839d91f56b34f32788bd3b00000049483045022100ac8f1a53f4cb1c2bb5651cea4a88d916c4ea650798c1e9beec631d9a4592d13d022057b581e122f2e26dfb516896b43741b61ce3d7896a0cd71c3467059632cc8af401ffffffffba006cc4a963a26c3af6a5eaeb0d865f45d4698ccee27a6e4551231e4c73f42355000000494830450221008ac71ce1959017a0946ba01e82677c8b7ef9d79821824d41fa6c4fdaa9b0886e022073939d695f863858c7fd15131c787e8eee3e417731eb5f20ea32fc1928986e7b01ffffffff0210270000000000002321020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9ac00000000000000002b6a29668bc765d66e2bda159248c9b531129d41e8ec96e033b0e505312002303f337e3a260100424c55520000000000000000000000000000000000000000

{
  "txid": "4e1314221fdf53205591134c38cebcf832073643dc393cc20552b6b4f9001796",
  "overwintered": true,
  "version": 4,
  "versiongroupid": "892f2085",
  "locktime": 0,
  "expiryheight": 0,
  "vin": [
    {
      "txid": "bd8827f3346bf5919d83851e3856f26844b7e524a2dadcc1fc332ba6685313b3",
      "vout": 59,
      "scriptSig": {
        "asm": "3045022100ac8f1a53f4cb1c2bb5651cea4a88d916c4ea650798c1e9beec631d9a4592d13d022057b581e122f2e26dfb516896b43741b61ce3d7896a0cd71c3467059632cc8af4[ALL]",
        "hex": "483045022100ac8f1a53f4cb1c2bb5651cea4a88d916c4ea650798c1e9beec631d9a4592d13d022057b581e122f2e26dfb516896b43741b61ce3d7896a0cd71c3467059632cc8af401"
      },
      "sequence": 4294967295
    },
    {
      "txid": "23f4734c1e2351456e7ae2ce8c69d4455f860debeaa5f63a6ca263a9c46c00ba",
      "vout": 85,
      "scriptSig": {
        "asm": "30450221008ac71ce1959017a0946ba01e82677c8b7ef9d79821824d41fa6c4fdaa9b0886e022073939d695f863858c7fd15131c787e8eee3e417731eb5f20ea32fc1928986e7b[ALL]",
        "hex": "4830450221008ac71ce1959017a0946ba01e82677c8b7ef9d79821824d41fa6c4fdaa9b0886e022073939d695f863858c7fd15131c787e8eee3e417731eb5f20ea32fc1928986e7b01"
      },
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00010000,
      "valueZat": 10000,
      "n": 0,
      "scriptPubKey": {
        "asm": "020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9 OP_CHECKSIG",
        "hex": "21020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9ac",
        "reqSigs": 1,
        "type": "pubkey",
        "addresses": [
          "RXL3YXG2ceaB6C5hfJcN4fvmLH2C34knhA"
        ]
      }
    },
    {
      "value": 0.00000000,
      "valueZat": 0,
      "n": 1,
      "scriptPubKey": {
        "asm": "OP_RETURN 668bc765d66e2bda159248c9b531129d41e8ec96e033b0e505312002303f337e3a260100424c555200",
        "hex": "6a29668bc765d66e2bda159248c9b531129d41e8ec96e033b0e505312002303f337e3a260100424c555200",
        "type": "nulldata"
      }
    }
  ],
  "vjoinsplit": [
  ],
  "valueBalance": 0.00000000,
  "vShieldedSpend": [
  ],
  "vShieldedOutput": [
  ]
}
```

Call `decode_opreturn` method with scriptPubKey hex as parameter:

For destination chain tx (KMD `OP_RETURN`):

```
curl -X POST http://localhost:21111/json_rpc -d '{"method":"decode_opreturn","params":{"hex":"6a29668bc765d66e2bda159248c9b531129d41e8ec96e033b0e505312002303f337e3a260100424c555200"}}'
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "embedded_desthash": "0000000000000000000000000000000000000000000000000000000000000000",
    "embedded_srchash": "7e333f3002203105e5b033e096ece8419d1231b5c9489215da2b6ed665c78b66",
    "height": 75322,
    "status": "OK",
    "symbol": "BLUR"
  }
}
```

For source chain tx (BLUR `OP_RETURN` from `btc_sendrawtransactin`):

```
curl -X POST http://localhost:21111/json_rpc -d '{"method":"decode_opreturn","params":{"hex":"6a498944420ee9b1050fc4924b4fa6c3e89853082157c865069acf6e2ddc9089d39e123101006c157b762dfa634be3262c4f76db37d6bfd1395dc18adb8ee644ce3ea78ec40d424c555200"}}'
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "embedded_desthash": "0dc48ea73ece44e68edb8ac15d39d1bfd637db764f2c26e34b63fa2d767b156c",
    "embedded_srchash": "9ed38990dc2d6ecf9a0665c85721085398e8c3a64f4b92c40f05b1e90e424489",
    "height": 78098,
    "status": "OK",
    "symbol": "BLUR"
  }
}
```

You may now cross-reference this information [on the Blur Network Testnet Explorer](https://testnetexplorer.blur.cash/search?value=7e333f3002203105e5b033e096ece8419d1231b5c9489215da2b6ed665c78b66).
