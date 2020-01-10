set(komodo_sources
  komodo_validation.cpp)

set(komodo_headers)

set(komodo_private_headers
  komodo_validation.h)

monero_private_headers(komodo
  ${komodo_private_headers})
monero_add_library(komodo
  ${komodo_sources}
  ${komodo_headers}
  ${komodo_private_headers})

target_link_libraries(komodo
  PRIVATE
    epee
    cncrypto
    common
    version
    multisig
    ${BTC_LIBRARY}
    ${SECP256K1_LIBRARY}
    ${EVENT_LIBRARY}
    ${Boost_CHRONO_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})
