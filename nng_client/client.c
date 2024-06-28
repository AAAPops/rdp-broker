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

#include "nng-client.h"

char *srv_list[] = { "tcp://127.0.0.1:5551",
                     "tcp://127.0.0.1:5552",
                     NULL };

int
main(int argc, char **argv)
{
	int rc;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <url> <user name>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    nng_client(argv[1], srv_list, 2);

	exit(0);
}
