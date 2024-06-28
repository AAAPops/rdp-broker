#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>

#include "common.h"
#include "utils.h"
#include "nng-extras.h"


typedef struct _info {
    char        usreName[USERNAME_MAX_LEN];
    uint32_t    usrPresent;
    uint64_t    usrJobTime;

    char        srvURL[128];
    uint32_t    srvAlive;
    uint32_t    srvLA;
} info_t;



/*  The client runs just once, and then returns. */
char *
nng_client(const char *username, char **URL_list, int URL_count)
{
    nng_socket sock;
    int        rv;
    nng_msg *  msg;
    uint32_t   tmp_u32;
    uint64_t   tmp_u64;

    info_t info[32] = {0};

    for (int i = 0; i < URL_count; ++i) {
        // --------------- Init connection----------------
        strcpy(info[i].usreName, username);
        strcpy(info[i].srvURL, URL_list[i]);
        info[i].usrPresent = 0;
        info[i].usrJobTime = 0;
        info[i].srvLA = 100;
        info[i].srvAlive = 0;

        if ((rv = nng_req0_open(&sock)) != 0) {
            nng_err("nng_req0_open()", rv);
            goto err_1;
        }

        nng_socket_set_ms(sock, NNG_OPT_SENDTIMEO, 5000);
        nng_socket_set_ms(sock, NNG_OPT_RECVTIMEO, 5000);

        if ((rv = nng_dial(sock, info[i].srvURL, NULL, 0)) != 0) {
            nng_err("nng_dial()", rv);
            goto err_1;
        }


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

        if ((rv = nng_sendmsg(sock, msg, 0)) != 0) {
            nng_err("nng_send()", rv);
            goto err_1;
        }


        // ----------------- Receive message ------------------
        if ((rv = nng_recvmsg(sock, &msg, 0)) != 0) {
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
        nng_close(sock);

        printf("-----\n");
        printf("User '%s'\n", info[i].usreName);
        printf("   - on Server      '%s'\n", info[i].srvURL);
        printf("   - srv LA:        %d\n",  info[i].srvLA);
        printf("   - srv Alive:     %d\n",  info[i].srvAlive);
        printf("   - \n");
        printf("   - user present:  %d\n",  info[i].usrPresent);
        printf("   - user job time: %ld\n", info[i].usrJobTime);
    }

    // Make decision if user PRESENT on any host
    uint64_t    tmpJobTime = UINT64_MAX;
    uint32_t    tmpLA = UINT32_MAX;
    char        tmpURL[128] = {0};
    char        *outputSrvIp = NULL;

    for (int i = 0; i < URL_count; ++i) {
        if ( (info[i].usrPresent == 1) && (info[i].usrJobTime < tmpJobTime))
        {
            tmpJobTime = info[i].usrJobTime;
            strcpy(tmpURL, info[i].srvURL);
        }
    }

    outputSrvIp = redirect_to_ip(tmpURL);
    if ( outputSrvIp != NULL ) {
        printf("\nRedirect user to existed session on Srv: %s <=== %s\n", outputSrvIp, tmpURL);
        return outputSrvIp;
    }


    // Make decision if user NOT present on any host
    for (int i = 0; i < URL_count; ++i) {
        if ( (info[i].srvAlive == 1) && (info[i].srvLA < tmpLA) )
        {
            tmpLA = info[i].srvLA;
            strcpy(tmpURL, info[i].srvURL);
        }
    }

    outputSrvIp = redirect_to_ip(tmpURL);
    if ( outputSrvIp != NULL ) {
        printf("\nChoose host for new user: %s <=== %s\n", outputSrvIp, tmpURL);
        return outputSrvIp;
    }


    return "8.8.8.8";
}