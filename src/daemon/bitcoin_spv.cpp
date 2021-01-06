// Copyright (c) 2018-2021, Blur Network
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


#include "boost/process.hpp"
#include "boost/filesystem.hpp"
#include "common/util.h"
#include "misc_log_ex.h"

int libbtc_launch(std::string const& command,
                   std::string const& arg1,
                   std::string const& arg2,
                   boost::filesystem::path const& logfile_path,
                   boost::filesystem::path const& relative_path_base,
                   uint32_t& process_id)
{
  boost::filesystem::path btc_logfile = { logfile_path / (command + ".log") } ;
  btc_logfile = boost::filesystem::absolute(btc_logfile, relative_path_base);

  boost::process::child c(command, arg1, arg2, boost::process::std_out > btc_logfile);

  if (c.running()) {
    process_id = c.id();
    MWARNING("Command: "<< std::string(command) << ", launched with args: " << arg1 << " " << arg2 << ", at PID: " << std::to_string(process_id));
    c.wait();
  }


   switch (c.exit_code())
    {
      case -1:
        MERROR("Forking of " << command << " failed!" << std::endl);
        break;
      case 0:
        MINFO("Forking of " << command << " successful." << std::endl);
        break;
      case 1:
        MERROR("Unexpected exit code in child process for command: " << command << std::endl);
        break;
    }

  return c.exit_code();

}
