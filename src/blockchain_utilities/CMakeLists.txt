# Copyright (c) 2018-2022, Blur Network
# Copyright (c) 2017-2018, The Masari Project
# Copyright (c) 2014-2018, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(blocksdat "")
if(PER_BLOCK_CHECKPOINT)
  if(APPLE)
    add_custom_command(OUTPUT blocksdat.o MAIN_DEPENDENCY ../blocks/checkpoints.dat COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && touch stub.c && ${CMAKE_C_COMPILER} -o stub.o -c stub.c COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && ${CMAKE_LINKER} ${LD_RAW_FLAGS} -r -sectcreate __DATA __blocks_dat ../blocks/checkpoints.dat -o ${CMAKE_CURRENT_BINARY_DIR}/blocksdat.o stub.o && rm -f stub.*)
  else()
    add_custom_command(OUTPUT blocksdat.o MAIN_DEPENDENCY ../blocks/checkpoints.dat COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && cp ../blocks/checkpoints.dat blocks.dat && ${CMAKE_LINKER} ${LD_RAW_FLAGS} -r -b binary -o ${CMAKE_CURRENT_BINARY_DIR}/blocksdat.o blocks.dat && rm -f blocks.dat)
  endif()
  set(blocksdat "blocksdat.o")
endif()

set(blockchain_import_sources
  blockchain_import.cpp
  bootstrap_file.cpp
  blocksdat_file.cpp
  )

set(blockchain_import_private_headers
  bootstrap_file.h
  blocksdat_file.h
  bootstrap_serialization.h
  )

monero_private_headers(blockchain_import
	  ${blockchain_import_private_headers})

set(blockchain_export_sources
  blockchain_export.cpp
  bootstrap_file.cpp
  blocksdat_file.cpp
  )

set(blockchain_export_private_headers
  bootstrap_file.h
  blocksdat_file.h
  bootstrap_serialization.h
  )

monero_private_headers(blockchain_export
	  ${blockchain_export_private_headers})


set(blockchain_blackball_sources
  blockchain_blackball.cpp
  )

set(blockchain_blackball_private_headers
  bootstrap_file.h
  blocksdat_file.h
  bootstrap_serialization.h
  )

monero_private_headers(blockchain_blackball
	  ${blockchain_blackball_private_headers})

set(blockchain_usage_sources
  blockchain_usage.cpp
  )

set(blockchain_usage_private_headers)

monero_private_headers(blockchain_usage
	  ${blockchain_usage_private_headers})



monero_add_executable(blockchain_import
  ${blockchain_import_sources}
  ${blockchain_import_private_headers}
  ${blocksdat})

target_link_libraries(blockchain_import
  PRIVATE
    blockchain_db
    p2p
    epee
    cryptonote_core
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})

if(ARCH_WIDTH)
  target_compile_definitions(blockchain_import
    PUBLIC -DARCH_WIDTH=${ARCH_WIDTH})
endif()

set_property(TARGET blockchain_import
	PROPERTY
	OUTPUT_NAME "blur-blockchain-import")
install(TARGETS blockchain_import DESTINATION bin)

monero_add_executable(blockchain_export
  ${blockchain_export_sources}
  ${blockchain_export_private_headers})

target_link_libraries(blockchain_export
  PRIVATE
    blockchain_db
    p2p
    cryptonote_core
    epee
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})

set_property(TARGET blockchain_export
	PROPERTY
	OUTPUT_NAME "blur-blockchain-export")
install(TARGETS blockchain_export DESTINATION bin)

monero_add_executable(blockchain_blackball
  ${blockchain_blackball_sources}
  ${blockchain_blackball_private_headers})

target_link_libraries(blockchain_blackball
  PRIVATE
    blockchain_db
    cryptonote_core
    p2p
    epee
    wallet
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})

set_property(TARGET blockchain_blackball
	PROPERTY
	OUTPUT_NAME "blur-blockchain-blackball")
install(TARGETS blockchain_blackball DESTINATION bin)


monero_add_executable(blockchain_usage
  ${blockchain_usage_sources}
  ${blockchain_usage_private_headers})

target_link_libraries(blockchain_usage
  PRIVATE
    blockchain_db
    cryptonote_core
    p2p
    epee
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})

set_property(TARGET blockchain_usage
	PROPERTY
	OUTPUT_NAME "blur-blockchain-usage")
install(TARGETS blockchain_usage DESTINATION bin)

