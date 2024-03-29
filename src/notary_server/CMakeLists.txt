
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
set(notary_server_sources
  notary_server.cpp
  ../../external/backward/backward.cpp)
else()
set(notary_server_sources
  notary_server.cpp)
endif()

set(notary_server_headers)

set(notary_server_private_headers
  notary_server.h
  notary_server_error_codes.h
  notary_server_commands_defs.h)

monero_private_headers(notary_server
  ${notary_server_private_headers})

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  monero_add_executable(notary_server
    ${notary_server_sources}
    ${notary_server_headers}
    ${notary_server_private_headers}
    ${BACKWARD_ENABLE})
  add_backward(notary_server)
  target_link_libraries(notary_server
    PRIVATE
      wallet
      epee
      rpc_base
      cryptonote_core
      cryptonote_protocol
      cncrypto
      p2p
      rpc
      common
#      ${BTC_LIBRARY}
#      ${SECP256K1_LIBRARY}
#      ${EVENT_LIBRARIES}
      ${Boost_CHRONO_LIBRARY}
      ${Boost_PROGRAM_OPTIONS_LIBRARY}
      ${Boost_FILESYSTEM_LIBRARY}
      ${Boost_THREAD_LIBRARY}
      ${CMAKE_THREAD_LIBS_INIT}
      ${EXTRA_LIBRARIES}
      ${BACKWARD_LIBRARIES}
      ${OPENSSL_LIBRARIES}
      ${UNWIND_LIBRARIES})
else()
  monero_add_executable(notary_server
    ${notary_server_sources}
    ${notary_server_headers}
    ${notary_server_private_headers})

  target_link_libraries(notary_server
    PRIVATE
      wallet
      epee
      rpc_base
      cryptonote_core
      cryptonote_protocol
      cncrypto
      p2p
      rpc
      common
#      ${BTC_LIBRARY}
#      ${SECP256K1_LIBRARY}
#      ${EVENT_LIBRARIES}
      ${Boost_CHRONO_LIBRARY}
      ${Boost_PROGRAM_OPTIONS_LIBRARY}
      ${Boost_FILESYSTEM_LIBRARY}
      ${Boost_THREAD_LIBRARY}
      ${CMAKE_THREAD_LIBS_INIT}
      ${EXTRA_LIBRARIES})
endif()

set_property(TARGET notary_server
  PROPERTY
    OUTPUT_NAME "blur-notary-server-rpc")
install(TARGETS notary_server DESTINATION bin)
