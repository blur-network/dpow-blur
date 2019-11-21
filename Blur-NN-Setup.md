# Blur Notary Node Setup for NN Operators

## Introduction

This guide will walk you through setting up your Blur Notary Server wallet.  At the end, you'll have a shiny new cryptonote keypair that can be used to create notarization transactions on BLUR (and all future CN coins integrating DPoW).

**A Brief Overview of How Keys Are Managed:** 

In coins that use the CryptoNote protocol, you will have two sets of keys.  These keys are 1.) a `viewkey` and 2.) a `spendkey`.  Viewkeys can be provided to any third party that you would like, so that they may view your transactions.  Viewkeys provide a means to do so, for audits (or whatever may be your reason), etc. without allowing that third party to spend the funds in your wallet.

Since we are shooting for transparency and auditable txs by all onlookers for DPoW, your viewkeys are automatically generated from your existing secp256k1 public keys.  So, your transactions will not be private! It is therefore imperative that you only use your notary wallet to create notarization transactions.

In the following steps, you will create a json-formatted file with your secp256k1 public key.  You'll provide a password within this file as well, that will be used to login to your notary server wallet, via both RPC and CLI interfaces.  In return, you will receive a private keypair.  After those are generated, we will need you to submit your public key to kolo, so that it can be hardcoded.

**To summarize:**

<u>**Things you need to send to kolo:**</u>
- Your newly created cryptonote public spendkey


<u>**Things you need to save**</u>
- Your private spendkey
- Your password
- Your generated wallet file

*Note: As long as you do not lose your private spendkey, you will be able to recover the wallet file, and set a new password*

## Download Binaries/Compile Source

First, download the binaries located here: https://github.com/blur-network/dpow-blur/releases, or compile from source. After you've done that, cd into the extracted folder, or if you're building from source, into `dpow-blur/build/release/bin`.


## Creating a JSON-Formatted Wallet File


**Step 1:** From within the directory which holds your downloaded binaries, create a json-formatted file with the following content: 


```
{
        "version": 1,
        "filename": "NAME_OF_YOUR_NOTARY_NODE",
        "scan_from_height": 0,
        "btc_pubkey":"YOUR_SECP256K1_PUBLIC_KEY",
        "password":"YOUR_SUPER_SECRET_PASSWORD"
}
```

Example:

![](https://i.ibb.co/BswkG8r/nn-4.png)


**Step 2.)** You must replace `NAME_OF_YOUR_NOTARY_NODE` with your notary node designation. This will become the name of your wallet file. (Example: `madmax_NA`)

**Step 3.)** Locate your node in the [table located in src/komodo/komodo_notaries.h](https://github.com/blur-network/dpow-blur/blob/dpow/src/komodo/komodo_notaries.h#L54), and ensure that the designation you entered for your wallet file, matches one of the nodes named there. 

**Step 4.)** Replace `YOUR_SECP256K1_PUBLIC_KEY` with your public key from this table, omitting the leading `02` or `03`.  In the following picture, the characters necessary are boxed in red.  This should be 64 characters in length. 

Example: ![](https://i.ibb.co/ScDYfb6/nn-1.png) 

**Step 5.)** Replace `YOUR_SUPER_SECRET_PASSWORD` with a super secret password of your choice.  Do not share this with anyone!  Write this password down, for offline storage. 

**Step 6.)** Save the file with the name `btc.json`. 


## Generate Your CryptoNote Keypair


**Step 1.)** Launch the blur daemon with `./blurd` or by clicking `blurd.exe`.  You do not need to wait for the daemon to sync. 

**Step 2.)** Launch the notary server with the following options: `./blur-notary-server-rpc --generate-from-btc-pubkey btc.json --rpc-bind-port=12121` 


You should see the following in your terminal: 

![](https://i.ibb.co/6Z8vdb7/nn-2.png)

**Step 3.)** Copy and paste your `public spendkey` somewhere, and send it to kolo. 

**Step 4.)** Close the wallet with a `ctrl + C` 


## Saving Your Secret Keys

**Step 1.)** Open the `blur-wallet-cli` with `./blur-wallet-cli` or by double clicking `blur-wallet-cli.exe`. 

**Step 2.)** Once prompted, enter the name of your wallet file, and hit `enter`.  This should match `NAME_OF_YOUR_NOTARY_NODE` above. 

**Step 3.)** Once prompted, enter the password you chose for `YOUR_SUPER_SECRET_PASSWORD`.  

**Step 4.)** Once your wallet opens, type the command `spendkey`.  You will be asked for a password, and then your private and public spendkey will be displayed. 

**Step 5.) Write down your private spendkey, and write it on the same paper you wrote your password** 

**Step 6.)** Tuck that paper away and never show it to anyone. 


Congratulations! You are now ready to go for notarizations on BLUR. 
