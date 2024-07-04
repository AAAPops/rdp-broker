// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitoar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This program serves as an example for how to write an async RPC service,
// using the RAW request/reply pattern and nn_poll.  The server receives
// messages and keeps them on a list, replying to them.

// To run this program, start the server as async_demo <url> -s
// Then connect to it with the client as async_client <url> <msec>.
//
//  % ./agent tcp://127.0.0.1:5555
//  % ./client tcp://127.0.0.1:5555 <user name>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>

#include "nng-common.h"
#include "utils.h"
#include "nng-extras.h"
#include "agent-config.h"

#define TAG "agent"

int run_as_daemon(void);

// Parallel is the maximum number of outstanding requests we can handle.
// This is *NOT* the number of threads in use, but instead represents
// outstanding work items.  Select a small number to reduce memory size.
// (Each one of these can be thought of as a request-reply loop.)
#ifndef PARALLEL
#define PARALLEL 32
#endif

const char *bash_script_name;


int exec_script(const char *script_name, char *args, char *output, int out_len)
{
    char *exec_str = malloc(strlen(script_name) + strlen(args) + 5 );
    sprintf(exec_str, "%s %s", script_name, args);

    /* Open the command for reading. */
    FILE *fp = popen(exec_str, "r");
    if (fp == NULL) {
        printf("Failed to run command\n" );
        exit(1);
    }

    /* Read the output a line at a time - output it. */
    while (fgets(output, out_len, fp) != NULL) {
        printf("%s", output);
    }

    /* close */
    pclose(fp);
    free(exec_str);

    return 0;
}


/* return:
 *      0%...100% - less is better
 */
int calc_srv_la(char *username) {

    char output[32] = {0};
    char cmd[64] = {0};

    sprintf(cmd, "%s %s", username, "getSrvLA");
    exec_script(bash_script_name, cmd, output, sizeof(output));
    //memdump("Output LA", output, sizeof(output), 16);
    for ( int i = 0; i < strlen(output); ++i ) {
        if ( output[i] == 0x0a )
            output[i] = 0;
    }
    //printf("--- getSrvLA: '%s'\n", output);

    return atoi(output);
}

/* return:
 *      0 - User absent
 *      1 - User present on host
 */
int is_user_on_host(char *username) {

    char output[32] = {0};
    char cmd[64] = {0};

    sprintf(cmd, "%s %s", username, "checkUser");
    exec_script(bash_script_name, cmd, output, sizeof(output));
    //memdump("Output LA", output, sizeof(output), 16);
    for ( int i = 0; i < strlen(output); ++i ) {
        if ( output[i] == 0x0a )
            output[i] = 0;
    }
    //printf("--- checkUser: '%s'\n", output);

    return atoi(output);
}

uint64_t calc_user_work_time(char *username) {

    char output[32] = {0};
    char cmd[64] = {0};

    sprintf(cmd, "%s %s", username, "getJobTime");
    exec_script(bash_script_name, cmd, output, sizeof(output));
    //memdump("Output LA", output, sizeof(output), 16);
    for ( int i = 0; i < strlen(output); ++i ) {
        if ( output[i] == 0x0a )
            output[i] = 0;
    }
    //printf("--- getJobTime: '%s'\n", output);

    return atol(output);
}

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.
struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *  aio;
	nng_socket sock;
	nng_msg *  msg;

    uint32_t     usrPresent;
    uint64_t     usrJobTime;
    uint32_t     srvLA;
};


void
server_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;
    char        *username;
    uint32_t     cmd;

    //printf("work->state = %d \n", work->state);

	switch (work->state) {
	case INIT:
        nng_log_debug(TAG, "INIT...");
		work->state = RECV;
		nng_recv_aio(work->sock, work->aio);
		break;
	case RECV:
        nng_log_debug(TAG, "RECV...");
		if ((rv = nng_aio_result(work->aio)) != 0) {
            nng_fatal("nng_recv_aio()", rv);
		}
		msg = nng_aio_get_msg(work->aio);
		if ((rv = nng_msg_trim_u32(msg, &cmd)) != 0) {
			// bad message, just ignore it.
			nng_msg_free(msg);
			nng_recv_aio(work->sock, work->aio);
			return;
		}

        if ( cmd == CMD_CHECK_USER ) {
            username = nng_msg_trim_str(msg);

            nng_log_info(TAG, "bash \"is_user_on_host(%s)\":", username);
            work->usrPresent = is_user_on_host(username);
            nng_log_info(TAG, "bash \"calc_user_work_time(%s)\":", username);
            work->usrJobTime = calc_user_work_time(username);
            nng_log_info(TAG, "bash \"calc_srv_la(%s)\":", username);
            work->srvLA = calc_srv_la(username);
        }

		work->msg   = msg;
		work->state = WAIT;
		nng_sleep_aio(1, work->aio);
		break;
	case WAIT:
        nng_log_debug(TAG, "WAIT...");
		// We could add more data to the message here.
        nng_msg_clear(work->msg);

        cmd = CMD_CHECK_USER;
        if ((rv = nng_msg_append_u32(work->msg, cmd)) != 0) {
            nng_fatal("nng_msg_append_u32()", rv);
        }
        if ((rv = nng_msg_append_u32(work->msg, work->usrPresent)) != 0) {
            nng_fatal("nng_msg_append_u32()", rv);
        }
        if ((rv = nng_msg_append_u64(work->msg, work->usrJobTime)) != 0) {
            nng_fatal("nng_msg_append_u64()", rv);
        }
        if ((rv = nng_msg_append_u32(work->msg, work->srvLA)) != 0) {
            nng_fatal("nng_msg_append_u32()", rv);
        }


		nng_aio_set_msg(work->aio, work->msg);
		work->msg   = NULL;
		work->state = SEND;
		nng_send_aio(work->sock, work->aio);
		break;
	case SEND:
        nng_log_debug(TAG, "SEND...");
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
            nng_fatal("nng_send_aio()", rv);
		}
		work->state = RECV;
		nng_recv_aio(work->sock, work->aio);
		break;
	default:
        nng_fatal("bad state!", NNG_ESTATE);
		break;
	}
}

struct work *
alloc_work(nng_socket sock)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
        nng_fatal("nng_alloc()", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, server_cb, w)) != 0) {
        nng_fatal("nng_aio_alloc()", rv);
	}
	w->state = INIT;
	w->sock  = sock;
	return (w);
}

void usage(const char* app, const char* invalid) {
    FILE *fp = stdout;

    fprintf(fp, "Usage: %s <-h|--help> <-f conf_file.ini> \n", app);

    exit (EXIT_FAILURE);
}

// The server runs forever.
int
server(const char *url)
{
	nng_socket   sock;
	struct work *works[PARALLEL];
	int          rv;
	int          i;

	/*  Create the socket. */
	rv = nng_rep0_open_raw(&sock);
	if (rv != 0) {
        nng_fatal("nng_rep0_open", rv);
	}

	for (i = 0; i < PARALLEL; i++) {
		works[i] = alloc_work(sock);
	}

	if ((rv = nng_listen(sock, url, NULL, 0)) != 0) {
        nng_fatal("nng_listen", rv);
	}


	for (i = 0; i < PARALLEL; i++) {
		server_cb(works[i]); // this starts them going (INIT state)
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}





int
main(int argc, char **argv)
{
	int rc;

    srv_conf_t srv_conf = {0};

    if ( init_server_config(argc, argv, &srv_conf) != 0 )
        exit(EXIT_FAILURE);

    bash_script_name = srv_conf.bash_file;

    nng_log_set_logger(nng_stderr_logger);
    nng_log_set_level(srv_conf.log_level);

    if( srv_conf.run_mode == RUN_MODE_DAEMON ) {
        nng_log_set_logger(nng_null_logger);

        if ( run_as_daemon() != 0)
            exit(EXIT_FAILURE);
    }

    rc = server(srv_conf.start_url);

	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

int run_as_daemon(void) {
    /* Our process ID and Session ID */
    pid_t pid, sid;
    FILE *fp = stdout;

    /* Fork off the parent process */
    pid = fork();
    if( pid < 0 ) {
        fprintf(fp, "fork() [%m] \n");
        return -1;
    }
    /* If we got a good PID, then we can exit the parent process. */
    if (pid > 0) { // Parent process has finished executing
        fprintf(fp, "Current process finished. Daemon starts... \n");
        exit(0);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here
    FILE *log_fp;
    log_fp = fopen(LOG_FILE_NAME, "w");
    if (log_fp) {
        log_set_fp(log_fp);
    } else {
        log_warn("fopen() [%m]");
        log_warn("Continue without logging into file '%s'", LOG_FILE_NAME);
    }
    */


    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        fprintf(fp, "setsid() [%m] \n");
        return -1;
    }

    /* Change the current working directory */
    if( chdir("/") < 0 ) {
        fprintf(fp, "chdir() [%m] \n");
        return -1;
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Daemon-specific initialization goes here */

    return 0;
}