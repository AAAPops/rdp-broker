#ifndef _AGENT_CONFIG_H
#define _AGENT_CONFIG_H

#include <nng/nng.h>

#define RUN_MODE_NORMAL   0
#define RUN_MODE_DAEMON   1

typedef struct _server_config
{
    const char  *cert;
    const char  *key;

    const char  *interface;
    UINT16      port;
    int         log_level;

    const char  *url_list[16];
    int         url_count;

    int         run_mode;
} srv_conf_t;


int init_server_config(int argc, char **argv, srv_conf_t *srv_conf);


#endif