// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitoar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// To run this program, start the server as async_demo <url> -s
// Then connect to it with the client as async_client <url> <msec>.
//
//  % ./agent tcp://127.0.0.1:5555
//  % ./client tcp://127.0.0.1:5555 <user name>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/req.h>

#include "nng-client.h"
#include "nng-common.h"
#include "utils.h"
#include "nng-extras.h"

#include "../broker-config.h"

#define AGENTS_COUNT    2

agent_t agents[AGENTS_COUNT] = {
        { "tcp://192.168.1.121:5555", 0 },
        { "tcp://192.168.1.122:5555", 0 }
};


int
main(int argc, char **argv)
{
	int rc;
    nng_socket socks[AGENTS_COUNT] = {0};

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <user name>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    nng_log_set_logger(nng_stderr_logger);
    nng_log_set_level(NNG_LOG_DEBUG);

    nng_init_agents(agents, AGENTS_COUNT);
    //----------------------------------------//

    nng_client(argv[1], agents, AGENTS_COUNT);
    //getchar();

	exit(0);
}
