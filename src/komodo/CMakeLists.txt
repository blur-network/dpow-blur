set(notary_sources
  komodo_validation.cpp
  notary_server.cpp)

set(notary_headers)

set(notary_private_headers
  komodo_validation.h
  komodo_rpcblockchain.h
  notary_server.h
  notary_server_error_codes.h
  notary_server_commands_defs.h)

monero_private_headers(notary_server
  ${notary_private_headers})
monero_add_executable(notary_server
  ${notary_sources}
  ${notary_headers}
  ${notary_private_headers})

target_link_libraries(notary_server
  PRIVATE
    wallet
    epee
    rpc_base
    cryptonote_core
    cncrypto
    common
    version
    ${Boost_CHRONO_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})
set_property(TARGET notary_server
  PROPERTY
    OUTPUT_NAME "blur-notary-server-rpc")
install(TARGETS notary_server DESTINATION bin)


