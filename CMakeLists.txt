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

set(CMAKE_C_STANDARD 99)

#set(MODULE_NAME "sfreerdp-server")
#set(MODULE_PREFIX "FREERDP_SERVER_SAMPLE")

include_directories(/opt/freerdp3/include/winpr3)
include_directories(/opt/freerdp3/include/freerdp3)

set(NNG_DIR /opt/nng/)
include_directories(${NNG_DIR}/include)

include_directories(nng_client)

set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")
#set(PARALLEL 1 CACHE STRING "Parallelism (min 4, max 1000)")

find_library(FREERDP-SERVER
		NAMES freerdp-server3
		PATHS "/opt/freerdp3/lib"
		)
message ("FREERDP-SERVER=${FREERDP-SERVER}")

find_library(FREERDP
		NAMES freerdp3
		PATHS "/opt/freerdp3/lib"
		)
message ("FREERDP=${FREERDP}")

find_library(WINPR
		NAMES winpr3
		PATHS "/opt/freerdp3/lib"
		)
message ("WINPR=${WINPR}")

find_library(INIH  NAMES inih)
message ("INIH=${INIH}")

find_package(Threads)


set(COMMON_NNG_SRC
		nng_src/common.h
		nng_src/utils.c
		nng_src/utils.h
		nng_src/nng-extras.c
		nng_src/nng-extras.h)

set(BASH_SCRIPT  agent.sh)

add_executable(_rdp-client  nng_src/client.c  nng_src/nng-client.c nng_src/nng-client.h  ${COMMON_NNG_SRC} )
target_link_libraries(_rdp-client ${NNG_DIR}/lib/libnng.a  Threads::Threads)
#target_compile_definitions(client PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})


add_executable(rdp-agent  nng_src/agent.c
		nng_src/agent-config.c
		nng_src/agent-config.h
		${COMMON_NNG_SRC} )
target_link_libraries(rdp-agent ${NNG_DIR}/lib/libnng.a  ${INIH}  Threads::Threads)
target_compile_definitions(rdp-agent PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})

set(BROKER_SRCS
		rdp-broker.c
		rdp-broker.h
		nng_src/nng-client.c
		nng_src/nng-client.h
		${COMMON_NNG_SRC}
	)


list(APPEND LIBS ${FREERDP-SERVER} ${FREERDP} ${WINPR} ${INIH})

add_executable(rdp-broker ${BROKER_SRCS})
target_link_libraries(rdp-broker ${LIBS} ${NNG_DIR}/lib/libnng.a  Threads::Threads)
#target_compile_definitions(rdp-broker PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})
#install(TARGETS ${MODULE_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)

