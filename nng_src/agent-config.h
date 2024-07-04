#ifndef _AGENT_CONFIG_H
#define _AGENT_CONFIG_H

#include <nng/nng.h>

#define RUN_MODE_NORMAL   0
#define RUN_MODE_DAEMON   1

typedef struct _server_config
{
    const char     *start_url;
    nng_log_level  log_level;

    const char     *bash_file;
    int            run_mode;
} srv_conf_t;


int init_server_config(int argc, char **argv, srv_conf_t *srv_conf);


#endif