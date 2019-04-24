message(STATUS "Adding bitcoin-specfic dependencies for DPoW integrations")
set(BITCOIN_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}" CACHE STRING "Bitcoin Include path")
set(BITCOIN_LIBRARY "bitcoin" CACHE STRING "Bitcoin Library name")

