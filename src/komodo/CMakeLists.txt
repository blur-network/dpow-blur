set(komodo_sources)

set(komodo_headers)
  
set(komodo_private_headers
  komodo_validation011.h
  komodo_rpcblockchain.h)

monero_private_headers(komodo
  ${komodo_private_headers})
monero_add_library(komodo
  ${komodo_sources}
  ${komodo_headers}
  ${komodo_private_headers})
target_link_libraries(komodo
  PUBLIC
    version
    common
    cncrypto
    blockchain_db
    ringct
    device
    ${Boost_DATE_TIME_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_SERIALIZATION_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
  PRIVATE
    ${EXTRA_LIBRARIES})
    
set(notary_sources
  notary_server.cpp)

set(notary_headers)

set(notary_private_headers
  notary_server.h)

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
    OUTPUT_NAME "notary-server-rpc")
install(TARGETS notary_server DESTINATION bin)
