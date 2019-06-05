// Copyright (c) 2019, Blur Network
// Copyright (c) 2017-2018, The Masari Project
// Copyright (c) 2014-2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
#include <boost/format.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/algorithm/string.hpp>
#include <cstdint>
#include "include_base_utils.h"
using namespace epee;

#include "notary_server.h"
#include "wallet/wallet_args.h"
#include "common/command_line.h"
#include "common/i18n.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "multisig/multisig.h"
//#include "notary_server_commands_defs.h"
#include "misc_language.h"
#include "string_coding.h"
#include "string_tools.h"
#include "crypto/hash.h"
#include "mnemonics/electrum-words.h"
#include "rpc/rpc_args.h"
#include "rpc/core_rpc_server_commands_defs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "notary_server.rpc"

namespace
{
  const command_line::arg_descriptor<std::string, true> arg_rpc_bind_port = {"rpc-bind-port", "Set the port for RPC communication"};
  const command_line::arg_descriptor<bool> arg_disable_rpc_login = {"disable-rpc-login", "Disable HTTP authentication for RPC connections served by this process"};
  const command_line::arg_descriptor<bool> arg_trusted_daemon = {"trusted-daemon", "Enable commands which rely on a trusted daemon", false};
  const command_line::arg_descriptor<std::string> arg_notary_wallet_dir = {"data-dir", "Directory for notary wallet and KMD state"};
  const command_line::arg_descriptor<bool> arg_prompt_for_password = {"prompt-for-password", "Prompts for password when not provided", false};

  constexpr const char default_rpc_username[] = "notary";

  boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify)
  {
    auto pwd_container = tools::password_container::prompt(verify, prompt);
    if (!pwd_container)
    {
      MERROR("failed to read password");
    }
    return pwd_container;
  }
}

namespace tools
{
  const char* notary_server::tr(const char* str)
  {
    return i18n_translate(str, "komodo::notary_server");
  }

  //------------------------------------------------------------------------------------------------------------------------------
  notary_server::notary_server():m_wallet(NULL), rpc_login_file(), m_stop(false), m_trusted_daemon(false), m_vm(NULL)
  {
  }
  //------------------------------------------------------------------------------------------------------------------------------
  notary_server::~notary_server()
  {
    if (m_wallet)
      delete m_wallet;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void notary_server::set_wallet(wallet2 *cr)
  {
    m_wallet = cr;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool notary_server::run()
  {
    m_stop = false;
    m_net_server.add_idle_handler([this](){
      try {
        if (m_wallet) m_wallet->refresh();
      } catch (const std::exception& ex) {
        LOG_ERROR("Exception at while refreshing, what=" << ex.what());
      }
      return true;
    }, 20000);
    m_net_server.add_idle_handler([this](){
      if (m_stop.load(std::memory_order_relaxed))
      {
        send_stop_signal();
        return false;
      }
      return true;
    }, 500);

    //DO NOT START THIS SERVER IN MORE THEN 1 THREADS WITHOUT REFACTORING
    return epee::http_server_impl_base<notary_server, connection_context>::run(1, true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void notary_server::stop()
  {
    if (m_wallet)
    {
      m_wallet->store();
      delete m_wallet;
      m_wallet = NULL;
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool notary_server::init(const boost::program_options::variables_map *vm)
  {
    auto rpc_config = cryptonote::rpc_args::process(*vm);
    if (!rpc_config)
      return false;

    m_vm = vm;
    tools::wallet2 *walvars;
    std::unique_ptr<tools::wallet2> tmpwal;

    if (m_wallet)
      walvars = m_wallet;
    else
    {
      tmpwal = tools::wallet2::make_dummy(*m_vm, password_prompter);
      walvars = tmpwal.get();
    }
    boost::optional<epee::net_utils::http::login> http_login{};
    std::string bind_port = command_line::get_arg(*m_vm, arg_rpc_bind_port);
    const bool disable_auth = command_line::get_arg(*m_vm, arg_disable_rpc_login);
    m_trusted_daemon = command_line::get_arg(*m_vm, arg_trusted_daemon);
    if (!command_line::has_arg(*m_vm, arg_trusted_daemon))
    {
      if (tools::is_local_address(walvars->get_daemon_address()))
      {
        MINFO(tr("Daemon is local, assuming trusted"));
        m_trusted_daemon = true;
      }
    }
    
    // TODO: Add bitcoin Pubkey logic here
    
    if (command_line::has_arg(*m_vm, arg_notary_wallet_dir))
    {
      m_notary_wallet_dir = command_line::get_arg(*m_vm, arg_notary_wallet_dir);
#ifdef _WIN32
#define MKDIR(path, mode)    mkdir(path)
#else
#define MKDIR(path, mode)    mkdir(path, mode)
#endif
      if (!m_notary_wallet_dir.empty() && MKDIR(m_notary_wallet_dir.c_str(), 0700) < 0 && errno != EEXIST)
      {
#ifdef _WIN32
        LOG_ERROR(tr("Failed to create directory ") + m_notary_wallet_dir);
#else
        LOG_ERROR((boost::format(tr("Failed to create directory %s: %s")) % m_notary_wallet_dir % strerror(errno)).str());
#endif
        return false;
      }
    }

    if (disable_auth)
    {
      if (rpc_config->login)
      {
        const cryptonote::rpc_args::descriptors arg{};
        LOG_ERROR(tr("Cannot specify --") << arg_disable_rpc_login.name << tr(" and --") << arg.rpc_login.name);
        return false;
      }
    }
    else // auth enabled
    {
      if (!rpc_config->login)
      {
        std::array<std::uint8_t, 16> rand_128bit{{}};
        crypto::rand(rand_128bit.size(), rand_128bit.data());
        http_login.emplace(
          default_rpc_username,
          string_encoding::base64_encode(rand_128bit.data(), rand_128bit.size())
        );

        std::string temp = "blur-wallet-rpc." + bind_port + ".login";
        rpc_login_file = tools::private_file::create(temp);
        if (!rpc_login_file.handle())
        {
          LOG_ERROR(tr("Failed to create file ") << temp << tr(". Check permissions or remove file"));
          return false;
        }
        std::fputs(http_login->username.c_str(), rpc_login_file.handle());
        std::fputc(':', rpc_login_file.handle());
        const epee::wipeable_string password = http_login->password;
        std::fwrite(password.data(), 1, password.size(), rpc_login_file.handle());
        std::fflush(rpc_login_file.handle());
        if (std::ferror(rpc_login_file.handle()))
        {
          LOG_ERROR(tr("Error writing to file ") << temp);
          return false;
        }
        LOG_PRINT_L0(tr("RPC username/password is stored in file ") << temp);
      }
      else // chosen user/pass
      {
        http_login.emplace(
          std::move(rpc_config->login->username), std::move(rpc_config->login->password).password()
        );
      }
      assert(bool(http_login));
    } // end auth enabled

    m_net_server.set_threads_prefix("RPC");
    auto rng = [](size_t len, uint8_t *ptr) { return crypto::rand(len, ptr); };
    return epee::http_server_impl_base<notary_server, connection_context>::init(
      rng, std::move(bind_port), std::move(rpc_config->bind_ip), std::move(rpc_config->access_control_origins), std::move(http_login)
    );
  }
  bool notary_server::not_open(epee::json_rpc::error& er)
  {
      er.code = -22;
      er.message = "No wallet file";
      return false;
  }
  }
  
int main(int argc, char** argv)
{

namespace po = boost::program_options;

  const auto arg_notary_wallet_file = wallet_args::arg_wallet_file();
  const auto arg_from_json = wallet_args::arg_generate_from_json();

  po::options_description desc_params(wallet_args::tr("Wallet options"));
  tools::wallet2::init_options(desc_params);
  command_line::add_arg(desc_params, arg_rpc_bind_port);
  command_line::add_arg(desc_params, arg_rpc_bind_port);
  command_line::add_arg(desc_params, arg_disable_rpc_login);
  command_line::add_arg(desc_params, arg_trusted_daemon);
  cryptonote::rpc_args::init_options(desc_params);
//  command_line::add_arg(desc_params, arg_btc_pubkey);
  command_line::add_arg(desc_params, arg_notary_wallet_file);
  command_line::add_arg(desc_params, arg_from_json);
  command_line::add_arg(desc_params, arg_notary_wallet_dir);
  command_line::add_arg(desc_params, arg_prompt_for_password);

  const auto vm = wallet_args::main(
    argc, argv,
    "notary-server-rpc [--wallet-file=<file>|--generate-from-json=<file>|--wallet-dir=<directory>] [--rpc-bind-port=<port>]",
    tools::notary_server::tr("This is the DPoW RPC notarization wallet. It needs to connect to a BLUR daemon to work correctly. If you are not intending to create notarization transactions, use the BLUR RPC wallet instead."),
    desc_params,
    po::positional_options_description(),
    [](const std::string &s, bool emphasis){ epee::set_console_color(emphasis ? epee::console_color_white : epee::console_color_default, true); std::cout << s << std::endl; if (emphasis) epee::reset_console_color(); },
    "notary-server-rpc.log",
    true
  );
  if (!vm)
  {
    return 1;
  }

  std::unique_ptr<tools::wallet2> wal;
  try
  {
    const bool testnet = tools::wallet2::has_testnet_option(*vm);
    const bool stagenet = tools::wallet2::has_stagenet_option(*vm);
    if (testnet && stagenet)
    {
      MERROR(tools::notary_server::tr("Can't specify more than one of --testnet and --stagenet"));
      return 1;
    }

    const auto notary_wallet_file = command_line::get_arg(*vm, arg_notary_wallet_file);
    const auto from_json = command_line::get_arg(*vm, arg_from_json);
    const auto notary_wallet_dir = command_line::get_arg(*vm, arg_notary_wallet_dir);
    const auto prompt_for_password = command_line::get_arg(*vm, arg_prompt_for_password);
    const auto password_prompt = prompt_for_password ? password_prompter : nullptr;

    if(!notary_wallet_file.empty() && !from_json.empty())
    {
      LOG_ERROR(tools::notary_server::tr("Can't specify more than one of --wallet-file and --generate-from-json"));
      return 1;
    }

    if (!notary_wallet_dir.empty())
    {
      wal = NULL;
      goto just_dir;
    }

    if (notary_wallet_file.empty() && from_json.empty())
    {
      LOG_ERROR(tools::notary_server::tr("Must specify --wallet-file or --generate-from-json or --wallet-dir"));
      return 1;
    }

    LOG_PRINT_L0(tools::notary_server::tr("Loading wallet..."));
    if(!notary_wallet_file.empty())
    {
      wal = tools::wallet2::make_from_file(*vm, notary_wallet_file, password_prompt).first;
    }
    else
    {
      try
      {
        wal = tools::wallet2::make_from_json(*vm, from_json, password_prompt);
      }
      catch (const std::exception &e)
      {
        MERROR("Error creating wallet: " << e.what());
        return 1;
      }
    }
    if (!wal)
    {
      return 1;
    }

    bool quit = false;
    tools::signal_handler::install([&wal, &quit](int) {
      assert(wal);
      quit = true;
      wal->stop();
    });

    wal->refresh();
    // if we ^C during potentially length load/refresh, there's no server loop yet
    if (quit)
    {
      MINFO(tools::notary_server::tr("Saving wallet..."));
      wal->store();
      MINFO(tools::notary_server::tr("Successfully saved"));
      return 1;
    }
    MINFO(tools::notary_server::tr("Successfully loaded"));
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(tools::notary_server::tr("Wallet initialization failed: ") << e.what());
    return 1;
  }
just_dir:
  tools::notary_server nrpc;
  if (wal) nrpc.set_wallet(wal.release());
  bool r = nrpc.init(&(vm.get()));
  CHECK_AND_ASSERT_MES(r, 1, tools::notary_server::tr("Failed to initialize wallet RPC server"));
  tools::signal_handler::install([&nrpc](int) {
    nrpc.send_stop_signal();
  });
  LOG_PRINT_L0(tools::notary_server::tr("Starting wallet RPC server"));
  try
  {
    nrpc.run();
  }
  catch (const std::exception &e)
  {
    LOG_ERROR(tools::notary_server::tr("Failed to run wallet: ") << e.what());
    return 1;
  }
  LOG_PRINT_L0(tools::notary_server::tr("Stopped wallet RPC server"));
  try
  {
    LOG_PRINT_L0(tools::notary_server::tr("Saving wallet..."));
    nrpc.stop();
    LOG_PRINT_L0(tools::notary_server::tr("Successfully saved"));
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(tools::notary_server::tr("Failed to save wallet: ") << e.what());
    return 1;
  }
  return 0;
}

