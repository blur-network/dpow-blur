# 2021 KMD S5-Testnet Instructions

### Things to do first

- Should already have a currently active notary node on 2021 testnet
OR: 
- Should compile `komodo` and `dPoW` repositories before following any instructions below

Some kmd/iguana dependencies are incompatible with `dpow-blur`/`blur-api-cpp`.  Building in a different order will result in build failures for komodo repositories.

- Add your notary node information to `3rdparty` and `m_notary_BLUR` with a PR to https://github.com/blur-network/dPoW

###  Download and install CMake 3.14+

Run the following commands:

```
cd ~
wget https://github.com/Kitware/CMake/releases/download/v3.15.2/cmake-3.15.2.tar.gz
tar xvzf cmake-3.15.2.tar.gz
cd cmake-3.15.2
./configure && make -j4
sudo make install
```
(CMake 3.15.2 was chosen arbitrarily, version 3.14 or above will work)


### Build blur binaries

Install dependencies: 

```
sudo apt install -y build-essential pkg-config libssl-dev libunwind-dev libevent-dev libsodium-dev binutils-dev libboost-all-dev autoconf libreadline-dev
```

Build `dpow-blur`:

```
cd ~
git clone https://github.com/blur-network/dpow-blur.git
cd dpow-blur
git submodule update --init
make -j4 release-static-linux-x86_64
```

### Build compatibility layer for iguana comms

Install dependencies:

```
sudo apt install libjsoncpp-dev curl libboost-program-options-dev libmicrohttpd-dev libargtable2-dev libssl-dev libcurl4-openssl-dev libhiredis-dev build-essential
```

Build and install `libjson-rpc-cpp`:

```
cd ~
git clone https://github.com/cinemast/libjson-rpc-cpp.git
cd libjson-rpc-cpp && mkdir build && cd build && cmake .. && make -j4
sudo make install
```

Build `blur-api-cpp`:

```
cd ~
git clone https://github.com/blur-network/blur-api-cpp.git
cd blur-api-cpp
git submodule update --init
mkdir build && cd build && cmake .. && make
```

###  Setup blur files for iguana

Add `blur_7779` file to `dPoW/iguana/coins` directory:

```
cd ~/dPoW/iguana/coins
wget https://raw.githubusercontent.com/blur-network/dPoW/blur-2021-testnet/iguana/coins/blur_7779
chmod 700 blur_7779
```

Add `m_notary_BLUR` to `iguana` directory:

```
cd ~/dPoW/iguana
wget https://raw.githubusercontent.com/blur-network/dPoW/blur-2021-testnet/iguana/m_notary_BLUR
chmod 700 m_notary_BLUR
```

Create a `wp_7779` file in `iguana` directory with the following contents:

```
curl --url "http://127.0.0.1:7779" --data "{\"method\":\"walletpassphrase\",\"params\":[\"<YOUR WIF OR PASSPHRASE>\", 9999999]}"
```

And change permissions:

```
chmod 700 wp_7779
```

### Launch blur daemon

```
cd ~/dpow-blur/build/release/bin
./blurd --testnet --p2p-bind-port=11111 --btc-pubkey <YOUR_NN_PUBKEY>
```

Then wait for chain to sync.  If you wish to run `blurd` in the background, add `--detach` to statup options

### Launch compat layer (blur-api-cpp)

Create a tmux session for `blurapi`: 

```
tmux new -s blurapi
```

Attach to the new session:

```
tmux a -t blurapi
```

Launch `blurapiserver` in session:

```
cd ~/blur-api-cpp/build/bin
./blurapiserver --blur-port=21111
```

Press 'Ctrl+B', then 'D' to detach from tmux session, afterward.

### Start a 3rdparty instance of iguana

```
cd ~/dPoW/iguana
./m_notary_BLUR
```
