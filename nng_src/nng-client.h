#ifndef _NNH_CLIENT_H
#define _NNH_CLIENT_H

#include "../broker-config.h"

char * nng_client(const char *username, agent_t *agent, int agent_count);

int nng_init_agents(agent_t *agent, int agent_count);

#endif