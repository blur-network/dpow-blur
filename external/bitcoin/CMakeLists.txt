


message(STATUS "Adding bitcoin-specfic dependencies for DPoW integrations")

cmake_minimum_required(VERSION 2.8.7)

project(bitcoin LANGUAGES C CXX)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

string(TOUPPER "${PROJECT_NAME}" setting_prefix)
function(get_setting setting_name setting_type setting_description)
    string(TOUPPER "${setting_prefix}_${setting_name}" setting_external_name)
    set("${setting_external_name}" "" CACHE "${setting_type}" "${setting_description}")
    set("${setting_name}" "${${setting_external_name}}" PARENT_SCOPE)
endfunction()


# Project files

set(source_files
  ${PROJECT_NAME}.cpp
  arith_uint256.cpp
  base58.cpp
  strencodings.cpp
  uint256.cpp)


set(header_files
  ${PROJECT_NAME}.h
  arith_uint256.h
  attributes.h
  base58.h
  byteswap.h
  common.h
  strencodings.h
  tinyformat.h
  uint256.h)

# Compile options

get_setting(target_arch STRING "Target system architecture (fed to the compiler's -march=...).")
if(NOT target_arch AND NOT CMAKE_CROSSCOMPILING)
    set(target_arch native)
endif()

set(compile_options
        # GNU, Clang
        $<$<OR:$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:GNU>>:
            # Optimizations
            -Os $<$<BOOL:${target_arch}>:-march=${target_arch}> -fno-exceptions
            # Warnings
            -Wall -Wextra -Wmissing-prototypes -Wdiv-by-zero -Wbad-function-cast -Wcast-align
            -Wcast-qual -Wfloat-equal -Wmissing-declarations -Wnested-externs -Wno-unknown-pragmas
            -Wpointer-arith -Wredundant-decls -Wstrict-prototypes -Wswitch-enum -Wno-type-limits>

        # MSVC
        $<$<C_COMPILER_ID:MSVC>:
            # Optimizations
            /Os /EHsc
            # Warnings
            /WX /W4
            /wd4197 # suppress warning "top-level volatile in cast is ignored"
            /wd4146 # suppress warning "unary minus operator applied to unsigned type, result still unsigned"
            /wd4310 # suppress warning "cast truncates constant value"
        >)

# Prefix project files with the project root

function(prefix_project_paths list_name)
    list(TRANSFORM "${list_name}"
            PREPEND "${PROJECT_SOURCE_DIR}/"
            OUTPUT_VARIABLE prefixed_list)
    set("project_${list_name}" ${prefixed_list} PARENT_SCOPE)
endfunction()


# Main library

add_library("${PROJECT_NAME}")
add_library("${PROJECT_NAME}::${PROJECT_NAME}" ALIAS "${PROJECT_NAME}")

target_sources("${PROJECT_NAME}" PRIVATE ${project_source_files})

target_include_directories("${PROJECT_NAME}" PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_options("${PROJECT_NAME}" PRIVATE ${compile_options})

# Installation

set(targets_export_name "${PROJECT_NAME}-targets")

install(TARGETS "${PROJECT_NAME}"
        EXPORT "${targets_export_name}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(FILES ${project_header_files}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

# CMake find_package() support

set(install_config_dir "${CMAKE_INSTALL_DATADIR}/cmake/${PROJECT_NAME}")

set(targets_export_file_name "${targets_export_name}.cmake")
set(targets_export_file "${PROJECT_BINARY_DIR}/${targets_export_file_name}")

install(EXPORT "${targets_export_name}"
        FILE "${targets_export_file_name}"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "${install_config_dir}")

set(config_file_name "${PROJECT_NAME}-config.cmake")
set(config_template_file "${PROJECT_SOURCE_DIR}/cmake/${config_file_name}.in")
set(config_file "${PROJECT_BINARY_DIR}/${config_file_name}")

CONFIGURE_PACKAGE_CONFIG_FILE("${config_template_file}" "${config_file}"
        INSTALL_DESTINATION "${install_config_dir}")

install(FILES "${config_file}"
        DESTINATION "${install_config_dir}")

export(EXPORT "${targets_export_name}"
        FILE "${targets_export_file}"
        NAMESPACE "${PROJECT_NAME}::")

export(PACKAGE "${PROJECT_NAME}")


set(BITCOIN_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}" CACHE STRING "Bitcoin Include path")
set(BITCOIN_LIBRARY_DIR "${CMAKE_CURRENT_SOURCE_DIR}" CACHE STRING "Bitcoin Library name")

