# FreeRDP: A Remote Desktop Protocol Implementation
# FreeRDP Sample Server cmake build script
#
# Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13)

project(rdp-broker)

set(CMAKE_C_STANDARD 11)
#set(CMAKE_C_STANDARD_REQUIRED ON)  # Require C11 support
#set(CMAKE_C_EXTENSIONS OFF)        # Disable compiler-specific extensions (optional)

set(CMAKE_INSTALL_PREFIX "/opt/rdp-broker" CACHE PATH "" FORCE)
# Overwrite with 'cmake -DCMAKE_INSTALL_PREFIX=/your/custom/path ..'

# Disable deprecated FreeRDP 3.x APIs
add_definitions(-DWITHOUT_FREERDP_3x_DEPRECATED)

#include_directories(/opt/freerdp3/include/winpr3)
#include_directories(/opt/freerdp3/include/freerdp3)

include_directories(nng_client)

set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")
#set(PARALLEL 1 CACHE STRING "Parallelism (min 4, max 1000)")

# Find FreeRDP3 packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(FREERDP3 REQUIRED freerdp3 winpr3)

include_directories(${FREERDP3_INCLUDE_DIRS})
#link_libraries(${FREERDP3_LIBRARIES})
#message ("FREERDP3_LIB=${FREERDP3_LIBRARIES}")
#message ("FREERDP3_INCLUDE=${FREERDP3_INCLUDE_DIRS}")

# Find FreeRDP3_Server packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(FREERDP3_SERVER REQUIRED freerdp-server3)

include_directories(${FREERDP3_SERVER_INCLUDE_DIRS})


# Find libinih packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(INIH REQUIRED inih)

include_directories(${INIH_INCLUDE_DIRS})


# Method 1: Preferred (pkg-config)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NNG QUIET nng)

# Method 2: Fallback (manual)
if(NOT NNG_FOUND)
	message("-- Checking for module 'nng'")
	find_path(NNG_INCLUDE_DIR NAMES nng.h PATHS /usr/include/nng)
	find_library(NNG_LIBRARY NAMES nng PATHS /usr/lib)

	if(NNG_INCLUDE_DIR)
		# Extract version from header
		file(STRINGS "${NNG_INCLUDE_DIR}/nng.h" NNG_MAJOR REGEX "^#define NNG_MAJOR_VERSION [0-9]+$")
		file(STRINGS "${NNG_INCLUDE_DIR}/nng.h" NNG_MINOR REGEX "^#define NNG_MINOR_VERSION [0-9]+$")
		file(STRINGS "${NNG_INCLUDE_DIR}/nng.h" NNG_PATCH REGEX "^#define NNG_PATCH_VERSION [0-9]+$")

		if(NNG_MAJOR AND NNG_MINOR AND NNG_PATCH)
			string(REGEX REPLACE "^#define NNG_MAJOR_VERSION ([0-9]+)$" "\\1" NNG_MAJOR "${NNG_MAJOR}")
			string(REGEX REPLACE "^#define NNG_MINOR_VERSION ([0-9]+)$" "\\1" NNG_MINOR "${NNG_MINOR}")
			string(REGEX REPLACE "^#define NNG_PATCH_VERSION ([0-9]+)$" "\\1" NNG_PATCH "${NNG_PATCH}")
			set(NNG_VERSION "${NNG_MAJOR}.${NNG_MINOR}.${NNG_PATCH}")
		endif()
	endif()

	if(NNG_INCLUDE_DIR AND NNG_LIBRARY)
		set(NNG_INCLUDE_DIRS ${NNG_INCLUDE_DIR})
		set(NNG_LIBRARIES ${NNG_LIBRARY})
		message("--   Found nng, version ${NNG_VERSION}")
	else()
		message(FATAL_ERROR "NNG library not found!")
	endif()
endif()

find_package(Threads)


set(COMMON_NNG_SRC
		nng_src/nng-common.h
		nng_src/utils.c
		nng_src/utils.h
		nng_src/nng-extras.c
		nng_src/nng-extras.h)

set(BASH_SCRIPT  agent.sh)

add_executable(_rdp-client  nng_src/client.c  nng_src/nng-client.c nng_src/nng-client.h  ${COMMON_NNG_SRC} )
target_link_libraries(_rdp-client ${NNG_LIBRARIES} Threads::Threads)



add_executable(rdp-agent
		nng_src/agent.c
		nng_src/agent-config.c
		nng_src/agent-config.h
		${COMMON_NNG_SRC} )
target_link_libraries(rdp-agent ${NNG_LIBRARIES}  ${INIH_LIBRARIES}  Threads::Threads)
target_compile_definitions(rdp-agent PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})

set(BROKER_SRCS
		rdp-broker.c
		rdp-broker.h
		version.h
		broker-config.c
		broker-config.h
		nng_src/nng-client.c
		nng_src/nng-client.h
		${COMMON_NNG_SRC}
	)


list(APPEND LIBS ${FREERDP3_SERVER_LIBRARIES} ${FREERDP3_LIBRARIES} ${WINPR_LIBRARIES} ${NNG_LIBRARIES}  ${INIH_LIBRARIES})

add_executable(rdp-broker ${BROKER_SRCS})
target_link_libraries(rdp-broker ${LIBS}   Threads::Threads)
#target_compile_definitions(rdp-broker PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})
#install(TARGETS ${MODULE_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)

message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")

install(
		TARGETS rdp-broker rdp-agent
		RUNTIME DESTINATION bin          # ${CMAKE_INSTALL_PREFIX}/bin
)

install(
		FILES rdp-broker.ini nng_src/rdp-agent.ini
		DESTINATION etc/rdp-broker       # ${CMAKE_INSTALL_PREFIX}/etc/rdp-broker
)

install(
		FILES nng_src/agent.sh
		DESTINATION bin       			# ${CMAKE_INSTALL_PREFIX}/bin

		PERMISSIONS
		OWNER_READ OWNER_WRITE OWNER_EXECUTE    # 700 (User: rwx)
		GROUP_READ GROUP_EXECUTE                # 750 (Group: r-x)
		WORLD_READ WORLD_EXECUTE                # 755 (Others: r-x)
)
