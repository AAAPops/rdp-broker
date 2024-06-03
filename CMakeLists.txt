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

project(freerdp-broker)

set(CMAKE_C_STANDARD 99)

#set(MODULE_NAME "sfreerdp-server")
#set(MODULE_PREFIX "FREERDP_SERVER_SAMPLE")

include_directories(/opt/freerdp3/include/winpr3)
include_directories(/opt/freerdp3/include/freerdp3)

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



set(SRCS
	freerdp-broker.c
	freerdp-broker.h
	)


list(APPEND LIBS ${FREERDP-SERVER} ${FREERDP} ${WINPR})

add_executable(freerdp-broker ${SRCS})
target_link_libraries(freerdp-broker ${LIBS})
#install(TARGETS ${MODULE_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)


