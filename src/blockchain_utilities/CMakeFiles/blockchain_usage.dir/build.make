# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/biz/github/repos/blur

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/biz/github/repos/blur

# Include any dependencies generated for this target.
include src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/depend.make

# Include the progress variables for this target.
include src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/progress.make

# Include the compile flags for this target's objects.
include src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/flags.make

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o: src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/flags.make
src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o: src/blockchain_utilities/blockchain_usage.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/biz/github/repos/blur/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o"
	cd /home/biz/github/repos/blur/src/blockchain_utilities && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o -c /home/biz/github/repos/blur/src/blockchain_utilities/blockchain_usage.cpp

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.i"
	cd /home/biz/github/repos/blur/src/blockchain_utilities && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/biz/github/repos/blur/src/blockchain_utilities/blockchain_usage.cpp > CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.i

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.s"
	cd /home/biz/github/repos/blur/src/blockchain_utilities && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/biz/github/repos/blur/src/blockchain_utilities/blockchain_usage.cpp -o CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.s

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o.requires:

.PHONY : src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o.requires

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o.provides: src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o.requires
	$(MAKE) -f src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/build.make src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o.provides.build
.PHONY : src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o.provides

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o.provides.build: src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o


# Object files for target blockchain_usage
blockchain_usage_OBJECTS = \
"CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o"

# External object files for target blockchain_usage
blockchain_usage_EXTERNAL_OBJECTS =

bin/blur-blockchain-usage: src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o
bin/blur-blockchain-usage: src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/build.make
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/librt.so
bin/blur-blockchain-usage: src/cryptonote_core/libcryptonote_core.a
bin/blur-blockchain-usage: src/blockchain_db/libblockchain_db.a
bin/blur-blockchain-usage: src/p2p/libp2p.a
bin/blur-blockchain-usage: src/libversion.a
bin/blur-blockchain-usage: contrib/epee/src/libepee.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_filesystem.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_system.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_thread.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/librt.so
bin/blur-blockchain-usage: src/cryptonote_core/libcryptonote_core.a
bin/blur-blockchain-usage: src/blockchain_db/libblockchain_db.a
bin/blur-blockchain-usage: external/db_drivers/liblmdb/liblmdb.a
bin/blur-blockchain-usage: src/multisig/libmultisig.a
bin/blur-blockchain-usage: src/ringct/libringct.a
bin/blur-blockchain-usage: src/cryptonote_basic/libcryptonote_basic.a
bin/blur-blockchain-usage: src/checkpoints/libcheckpoints.a
bin/blur-blockchain-usage: src/device/libdevice.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libpcsclite.so
bin/blur-blockchain-usage: src/ringct/libringct_basic.a
bin/blur-blockchain-usage: src/common/libcommon.a
bin/blur-blockchain-usage: external/unbound/libunbound.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_regex.a
bin/blur-blockchain-usage: src/crypto/libcncrypto.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_date_time.a
bin/blur-blockchain-usage: src/libversion.a
bin/blur-blockchain-usage: contrib/epee/src/libepee.a
bin/blur-blockchain-usage: external/easylogging++/libeasylogging.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libssl.so
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/blur-blockchain-usage: external/miniupnpc/libminiupnpc.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_chrono.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_program_options.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_filesystem.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_system.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_thread.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/libboost_serialization.a
bin/blur-blockchain-usage: /usr/lib/x86_64-linux-gnu/librt.so
bin/blur-blockchain-usage: src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/biz/github/repos/blur/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../bin/blur-blockchain-usage"
	cd /home/biz/github/repos/blur/src/blockchain_utilities && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/blockchain_usage.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/build: bin/blur-blockchain-usage

.PHONY : src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/build

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/requires: src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/blockchain_usage.cpp.o.requires

.PHONY : src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/requires

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/clean:
	cd /home/biz/github/repos/blur/src/blockchain_utilities && $(CMAKE_COMMAND) -P CMakeFiles/blockchain_usage.dir/cmake_clean.cmake
.PHONY : src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/clean

src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/depend:
	cd /home/biz/github/repos/blur && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/biz/github/repos/blur /home/biz/github/repos/blur/src/blockchain_utilities /home/biz/github/repos/blur /home/biz/github/repos/blur/src/blockchain_utilities /home/biz/github/repos/blur/src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/blockchain_utilities/CMakeFiles/blockchain_usage.dir/depend

