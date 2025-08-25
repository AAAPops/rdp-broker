#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>

#include "nng-common.h"
#include "utils.h"
#include "nng-extras.h"
#include "../broker-config.h"


typedef struct {
    char        usreName[USERNAME_MAX_LEN];
    uint32_t    usrPresent;
    uint64_t    usrJobTime;

    char        srvURL[128];
    uint32_t    srvAlive;
    uint32_t    srvLA;
} info_t;



/*  The client runs just once, and then returns. */
char *
nng_client(const char *username, agent_t *agent, int agent_count)
{
    //nng_socket sock;
    int        rv;
    nng_msg *  msg;
    uint32_t   tmp_u32;
    uint64_t   tmp_u64;

    info_t info[32] = {0};

    for (int i = 0; i < agent_count; ++i) {
        // --------------- Init connection----------------
        strcpy(info[i].usreName, username);
        strcpy(info[i].srvURL, agent[i].url);
        info[i].usrPresent = 0;
        info[i].usrJobTime = 0;
        info[i].srvLA = 100;
        info[i].srvAlive = 0;

        // ----------------- Send message ------------------
        if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
            nng_err("nng_msg_alloc()", rv);
            goto err_1;
        }

        tmp_u32 = CMD_CHECK_USER;
        if ((rv = nng_msg_append_u32(msg, tmp_u32)) != 0) {
            nng_err("nng_msg_append_u32()", rv);
            goto err_1;
        }
        if ((rv = nng_msg_append_str(msg, info[i].usreName)) != 0) {
            nng_err("nng_msg_append_u32()", rv);
            goto err_1;
        }

        if ((rv = nng_sendmsg(agent[i].sock, msg, 0)) != 0) {
            nng_err("nng_send()", rv);
            goto err_1;
        }


        // ----------------- Receive message ------------------
        if ((rv = nng_recvmsg(agent[i].sock, &msg, 0)) != 0) {
            nng_err("nng_recvmsg()", rv);
            goto err_1;
        }

        if ((rv = nng_msg_trim_u32(msg, &tmp_u32)) != 0) {
            nng_err("nng_msg_append_u32()", rv);
            goto err_1;
        }
        if ((rv = nng_msg_trim_u32(msg, &tmp_u32)) != 0) {
            nng_err("nng_msg_append_u32()", rv);
            goto err_1;
        }
        info[i].usrPresent = tmp_u32;

        if ((rv = nng_msg_trim_u64(msg, &tmp_u64)) != 0) {
            nng_err("nng_msg_append_u64()", rv);
            goto err_1;
        }
        info[i].usrJobTime = tmp_u64;

        if ((rv = nng_msg_trim_u32(msg, &tmp_u32)) != 0) {
            nng_err("nng_msg_append_u32()", rv);
            goto err_1;
        }
        info[i].srvLA = tmp_u32;

        info[i].srvAlive = 1;

    err_1:
        nng_msg_free(msg);
        //nng_close(sock);

        nng_log_info(NULL, "-----");
        if ( info[i].usrPresent == UINT32_MAX )
            nng_log_info(NULL, "User '%s' not present...", info[i].usreName);
        else
            nng_log_info(NULL, "User '%s'", info[i].usreName);

        nng_log_info(NULL, "   - on Server          '%s'", info[i].srvURL);
        nng_log_info(NULL, "   - srv LA:            %d%%",  info[i].srvLA);
        nng_log_info(NULL, "   - srv Alive:         %d",  info[i].srvAlive);
        nng_log_info(NULL, "   -");

        if ( info[i].usrPresent == UINT32_MAX )
            nng_log_info(NULL, "   - Xrdp session:      %d",  0);
        else
            nng_log_info(NULL, "   - Xrdp session:      %d",  info[i].usrPresent);

        nng_log_info(NULL, "   - Xrdp session time: %ld sec.", info[i].usrJobTime);
    }

    // Make decision if user's session  PRESENT on any host
    uint64_t    tmpJobTime = 0;
    uint32_t    tmpLA = UINT32_MAX;
    char        tmpURL[128] = {0};
    char        *outputSrvIp = NULL;

    for (int i = 0; i < agent_count; i++) {
        if ( (info[i].usrPresent == 1) && (info[i].usrJobTime > tmpJobTime))
        {
            tmpJobTime = info[i].usrJobTime;
            strcpy(tmpURL, info[i].srvURL);
        }
    }

    outputSrvIp = redirect_to_ip(tmpURL);
    if ( outputSrvIp != NULL ) {
        nng_log_info(NULL, "---");
        nng_log_info(NULL, "Redirect user to existed session on Srv: %s <=== %s\n",
                     outputSrvIp, tmpURL);
        return outputSrvIp;
    }


    // Make decision if user's session NOT present on any host
    for (int i = 0; i < agent_count; i++) {
        // Skip agent if User absent on Server
        if ( info[i].usrPresent == UINT32_MAX )
            continue;

        if ( (info[i].srvAlive == 1) && (info[i].srvLA < tmpLA) )
        {
            tmpLA = info[i].srvLA;
            strcpy(tmpURL, info[i].srvURL);
        }
    }

    outputSrvIp = redirect_to_ip(tmpURL);
    if ( outputSrvIp != NULL ) {
        nng_log_info(NULL, "---");
        nng_log_info(NULL, "Choose host for new user: %s <=== %s\n",
                     outputSrvIp, tmpURL);
        return outputSrvIp;
    }


    return NULL;
}


int nng_init_agents(agent_t *agent, int agent_count) {
    int rv;
    nng_dialer dialer;

    for (int i = 0; i < agent_count; ++i) {

        if ((rv = nng_req0_open(&agent[i].sock)) != 0) {
            nng_err("nng_req0_open()", rv);
            goto err_1;
        }

        nng_socket_set_ms(agent[i].sock, NNG_OPT_SENDTIMEO, 300);
        nng_socket_set_ms(agent[i].sock, NNG_OPT_RECVTIMEO, 5000);

        if ((rv = nng_dialer_create(&dialer, agent[i].sock, agent[i].url)) != 0) {
            nng_err("nng_dialer_create()", rv);
            goto err_1;
        }

        nng_dialer_set_bool(dialer, NNG_OPT_TCP_KEEPALIVE, true);

        nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

        err_1:
        ;
    }

    return 0;
}