#ifndef _AGENT_CONFIG_H
#define _AGENT_CONFIG_H

#include <stdint.h>
#include <nng/nng.h>

#define RUN_MODE_NORMAL   0
#define RUN_MODE_DAEMON   1

#define AGENT_MAX_NUM     16

typedef struct
{
    char        *url;
    nng_socket  sock;

} agent_t;

typedef struct
{
    const char  *cert;
    const char  *key;

    const char  *interface;
    uint16_t    port;
    int         log_level;

    agent_t     agent[AGENT_MAX_NUM];
    int         agents_count;

    int         run_mode;
} srv_conf_t;


int init_server_config(int argc, char **argv, srv_conf_t *srv_conf);


#endif