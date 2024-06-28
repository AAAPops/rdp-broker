#
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required (VERSION 2.8.12)

project(nng-broker)

set(PARALLEL 128 CACHE STRING "Parallelism (min 4, max 1000)")
#set(PARALLEL 1 CACHE STRING "Parallelism (min 4, max 1000)")

#find_package(nng CONFIG REQUIRED)

set(NNG_DIR /opt/nng/)

include_directories(${NNG_DIR}/include)

find_package(Threads)

set(COMMON_SRC  common.h  utils.c utils.h  nng-extras.c  nng-extras.h)
set(BASH_SCRIPT  agent.sh)

add_executable(client  client.c  nng-client.c nng-client.h  ${COMMON_SRC} )
target_link_libraries(client ${NNG_DIR}/lib/libnng.a  Threads::Threads)
target_compile_definitions(client PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})


add_executable(agent  agent.c  ${COMMON_SRC} )
target_link_libraries(agent ${NNG_DIR}/lib/libnng.a  Threads::Threads)
target_compile_definitions(agent PRIVATE NNG_ELIDE_DEPRECATED PARALLEL=${PARALLEL})