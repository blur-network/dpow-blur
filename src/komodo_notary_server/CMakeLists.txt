set(komodo_notary_server_sources
  notary_server.cpp)

set(komodo_notary_server_headers)

set(komodo_notary_server_private_headers
  notary_server.h
  notary_server_error_codes.h
  notary_server_commands_defs.h)

monero_private_headers(komodo_notary_server
  ${komodo_notary_server_private_headers})
monero_add_executable(komodo_notary_server
  ${komodo_notary_server_sources}
  ${komodo_notary_server_headers}
  ${komodo_notary_server_private_headers})

target_link_libraries(komodo_notary_server
  PRIVATE
    wallet
    epee
    rpc_base
    cryptonote_core
    cncrypto
    rpc
    common
    version
    ${BTC_LIBRARY}
    ${SECP256K1_LIBRARY}
    ${EVENT_LIBRARY}
    ${Boost_CHRONO_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})

set_property(TARGET komodo_notary_server
  PROPERTY
    OUTPUT_NAME "blur-notary-server-rpc")
install(TARGETS komodo_notary_server DESTINATION bin)


