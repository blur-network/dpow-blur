#pragma once

#define GIT_RETRIEVED_STATE true
#define GIT_HEAD_SHA1 "08d767aae758606dabcb8d73ca1f1528ad1b48c9"
#define GIT_IS_DIRTY true

#define DEF_MONERO_VERSION "0.2.0.0-testnet"
#define DEF_MONERO_RELEASE_NAME "Radiance"
#define DEF_MONERO_VERSION_FULL(s,y) DEF_MONERO_VERSION#s#y

namespace cryptonote {

static char const*  MONERO_VERSION_TAG = MONERO_VERSION_TAG;
static char const* MONERO_VERSION = DEF_MONERO_VERSION;
static char const* MONERO_RELEASE_NAME = DEF_MONERO_RELEASE_NAME;
static char const* MONERO_VERSION_FULL = DEF_MONERO_VERSION_FULL(-,08d767aae758606dabcb8d73ca1f1528ad1b48c9);

}
